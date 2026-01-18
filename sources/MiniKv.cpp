//
// Created by Ivor_Aif on 2026/1/12.
//

#include "../headers/MiniKv.h"

MiniKv::MiniKv(User& user) : user(user) {
}

MiniKv::~MiniKv() = default;

void MiniKv::load() {
    this->kvs.clear();
    Persistence::initial();
    if (const std::filesystem::path dir = Persistence::getPath() + "/" + user.getFilename() + ".mkv"; std::filesystem::exists(dir) && std::filesystem::is_regular_file(dir)) {
        const std::string filename = dir.string();
        std::ifstream ifs(filename, std::ios::binary);
        ifs.exceptions(std::ios::failbit | std::ios::badbit);
        auto readCv = [&ifs](std::vector<uint8_t>& val) {
            uint32_t size = 0;
            ifs.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (size > 1 << 24) { // 16 MiB
                throw std::runtime_error("File size is too large.");
            }
            val.resize(size);
            ifs.read(reinterpret_cast<char*>(val.data()), size);
        };
        std::vector<uint8_t> masterKey;
        EncryptedBlob enc;
        try {
            readCv(masterKey);
            readCv(enc.iv);
            if (enc.iv.size() != 12) {
                throw std::runtime_error("IV is not correct.");
            }
            readCv(enc.ciphertext);
            readCv(enc.tag);
            if (enc.tag.size() != 16) {
                throw std::runtime_error("Tag is not correct.");
            }
        } catch (const std::exception& err) {
            std::cerr << "Warning: Your saves has been corrupted, all data lost: " << err.what() << " ." << std::endl;
            ifs.close();
            std::ofstream(dir).close();
            return;
        }
        ifs.close();
        if (std::vector<uint8_t> dec; CryptoFile::decrypt(masterKey, enc, dec)) {
            size_t pos = 0;
            const std::string str(dec.begin(), dec.end());
            auto readL = [&pos, &str](size_t& len) {
                len = 0;
                while (pos < str.size() && std::isdigit(str[pos])) {
                    len = 10 * len + str[pos++] - '0';
                }
                if (pos < str.size()) {
                    pos++;
                }
            };
            while (pos < str.size()) {
                size_t kl = 0, vl = 0;
                readL(kl);
                if (pos > str.size()) {
                    break;
                }
                if (pos + kl > str.size()) {
                    break;
                }
                std::string kk = str.substr(pos, kl);
                pos += kl;
                readL(vl);
                if (pos + vl > str.size()) {
                    break;
                }
                std::string vv = str.substr(pos, vl);
                pos += vl;
                this->kvs.emplace(kk, vv);
            }
        } else {
            std::cerr << "Warning: Your saves has been tampered with! All data lost." << std::endl;
            std::ofstream(dir).close();
        }
    }
}

void MiniKv::edit() {
    const std::vector<uint8_t> salt = KeyManager::generateSalt();
    const std::vector<uint8_t> masterKey = KeyManager::deriveUserKey(user.getFileSalt(), salt);
    std::string str;
    for (const auto& [kk, vv]: this->kvs) {
        str += std::to_string(kk.size()) + ':' + kk + std::to_string(vv.size()) + ':' + vv;
    }
    auto [iv, ciphertext, tag] = CryptoFile::encrypt(masterKey, std::vector<uint8_t>(str.begin(), str.end()));
    const std::string filename = Persistence::getPath() + "/" + user.getFilename() + ".mkv";
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    auto writeCv = [&ofs](const std::vector<uint8_t>& val) {
        const uint32_t size = val.size();
        ofs.write(reinterpret_cast<const char*>(&size), sizeof(size));
        if (size > 0) {
            ofs.write(reinterpret_cast<const char*>(val.data()), size);
        }
    };
    writeCv(masterKey);
    writeCv(iv);
    writeCv(ciphertext);
    writeCv(tag);
    ofs.close();
}

bool MiniKv::put(const std::string& key, const std::string& value) {
    if (this->kvs.contains(key)) {
        return false;
    }
    this->kvs.emplace(key, value);
    this->edit();
    return true;
}

bool MiniKv::modify(const std::string& key, const std::string& value) {
    if (this->kvs.contains(key)) {
        this->kvs[key] = value;
        this->edit();
        return true;
    }
    return false;
}

std::string MiniKv::get(const std::string &key) {
    if (this->kvs.contains(key)) {
        return this->kvs[key];
    }
    return "";
}

bool MiniKv::del(const std::string& key) {
    if (this->kvs.contains(key)) {
        this->kvs.erase(key);
        return true;
    }
    return false;
}

void MiniKv::clear() {
    this->kvs.clear();
    this->edit();
}

std::vector<std::string> MiniKv::skim() const {
    std::vector<std::string> keys;
    for (const auto& key: this->kvs | std::views::keys) {
        keys.push_back(key);
    }
    return keys;
}
