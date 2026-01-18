//
// Created by Ivor_Aif on 2026/1/10.
//

#include "../headers/Persistence.h"

const std::string Persistence::path = "./saves";
const std::string Persistence::users = "users";

bool Persistence::initial(const bool regist) {
    const std::filesystem::path dir = path;
    if (std::filesystem::exists(dir) && std::filesystem::is_directory(dir)) {
        if (std::filesystem::exists(path + "/" + users + ".mkv") && std::filesystem::is_regular_file(path + "/" + users + ".mkv")) {
            return true;
        }
        if (!regist) {
            return false;
        }
        std::ofstream(path + "/" + users + ".mkv").close();
    }
    if (!regist) {
        return false;
    }
    std::filesystem::create_directory(dir);
    std::ofstream(path + "/" + users + ".mkv").close();
    return false;
}

const std::string& Persistence::getPath() {
    return path;
}

std::vector<User> Persistence::load() {
    if (Persistence::initial(false)) {
        const std::string filename = path + "/" + users + ".mkv";
        std::ifstream ifs(filename, std::ios::binary);
        auto readCv = [&ifs](std::vector<uint8_t>& val) {
            uint32_t size = 0;
            ifs.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (size > 1 << 24) { // 16 MiB
                throw std::runtime_error("File size is too large.");
            }
            val.resize(size);
            ifs.read(reinterpret_cast<char*>(val.data()), size);
        };
        std::vector<uint8_t> masterKey = KeyManager::loadOrCreateMasterKey();
        EncryptedBlob enc;
        try {
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
            std::cerr << "Warning: User file has been corrupted, all data lost: " << err.what() << " ." << std::endl;
            ifs.close();
            for (const auto& entry: std::filesystem::directory_iterator(path)) {
                if (entry.is_regular_file() && entry.path().extension() == ".mkv") {
                    std::filesystem::remove(entry.path());
                }
            }
            std::ofstream(filename).close();
            return {};
        }
        ifs.close();
        if (std::vector<uint8_t> dec; CryptoFile::decrypt(masterKey, enc, dec)) {
            size_t offset = 0;
            auto require = [&offset, &dec](const size_t nn) {
                if (offset + nn > dec.size())
                    throw std::runtime_error("Corrupted decrypted data.");
            };
            auto read32 = [&offset, &dec, require]() -> uint32_t {
                require(4);
                const uint32_t val = dec[offset] << 24 | dec[offset + 1] << 16 | dec[offset + 2] << 8 | dec[offset + 3];
                offset += 4;
                return val;
            };
            uint32_t count = read32();
            std::vector<User> usrs;
            usrs.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                uint32_t len = read32();
                require(len);
                std::string blob(reinterpret_cast<const char*>(dec.data() + offset), len);
                offset += len;
                usrs.emplace_back(blob);
            }
            return usrs;
        } else {
            std::cerr << "Warning: User file("<< filename <<") has been tampered with!" << std::endl;
            for (const auto& entry: std::filesystem::directory_iterator(path)) {
                if (entry.is_regular_file() && entry.path().extension() == ".mkv") {
                    std::filesystem::remove(entry.path());
                }
            }
            std::ofstream(filename).close();
        }
    }
    return {};
}

void Persistence::save(const std::vector<User>& usrs) {
    Persistence::initial();
    std::string info;
    auto write32 = [&info](const uint32_t val) {
        info.push_back(static_cast<int8_t>(val >> 24 & 0xff));
        info.push_back(static_cast<int8_t>(val >> 16 & 0xff));
        info.push_back(static_cast<int8_t>(val >> 8 & 0xff));
        info.push_back(static_cast<int8_t>(val & 0xff));
    };
    write32(usrs.size());
    for (const User& user: usrs) {
        std::string usr = user.u2s();
        write32(usr.size());
        info.append(usr);
    }
    remove(KeyManager::getMasterKeyFile().c_str());
    const std::vector<uint8_t> masterKey = KeyManager::loadOrCreateMasterKey();
    auto [iv, ciphertext, tag] = CryptoFile::encrypt(masterKey, std::vector<uint8_t>(info.begin(), info.end()));
    const std::string filename = path + "/" + users + ".mkv";
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    auto writeCv = [&ofs](const std::vector<uint8_t>& val) {
        const uint32_t size = val.size();
        ofs.write(reinterpret_cast<const char*>(&size), sizeof(size));
        if (size > 0) {
            ofs.write(reinterpret_cast<const char*>(val.data()), size);
        }
    };
    writeCv(iv);
    writeCv(ciphertext);
    writeCv(tag);
    ofs.close();
}

EncryptedBlob CryptoFile::encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
    EncryptedBlob blob;
    blob.iv.resize(12);
    blob.tag.resize(16);
    blob.ciphertext.resize(plaintext.size());
    RAND_bytes(blob.iv.data(), static_cast<int>(blob.iv.size()));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(blob.iv.size()), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), blob.iv.data());
    EVP_EncryptUpdate(ctx, blob.ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()));
    EVP_EncryptFinal_ex(ctx, blob.ciphertext.data() + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(blob.tag.size()), blob.tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return blob;
}

bool CryptoFile::decrypt(const std::vector<uint8_t>& key, const EncryptedBlob& blob, std::vector<uint8_t>& plaintext) {
    plaintext.resize(blob.ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(blob.iv.size()), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), blob.iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, blob.ciphertext.data(), static_cast<int>(blob.ciphertext.size()));
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(blob.tag.size()), const_cast<uint8_t*>(blob.tag.data()));
    const int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;
}
