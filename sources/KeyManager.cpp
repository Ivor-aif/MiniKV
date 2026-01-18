//
// Created by Ivor_Aif on 2026/1/11.
//

#include "../headers/KeyManager.h"

namespace {
    constexpr size_t KEY_LEN = 32;
    constexpr int PBKDF2_ITERS = 100000;
    std::string MASTER_KEY_FILE = Persistence::getPath() + "/master.key";
}

std::vector<uint8_t> KeyManager::loadOrCreateMasterKey() {
    Persistence::initial();
    if (std::ifstream in(MASTER_KEY_FILE, std::ios::binary); in.good()) {
        std::vector<uint8_t> key(KEY_LEN);
        in.read(reinterpret_cast<char*>(key.data()), static_cast<long long>(key.size()));
        return key;
    }
    std::vector<uint8_t> key(KEY_LEN);
    RAND_bytes(key.data(), static_cast<int>(key.size()));
    std::ofstream out(MASTER_KEY_FILE, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(key.data()), static_cast<long long>(key.size()));
    return key;
}

std::vector<uint8_t> KeyManager::deriveUserKey(const std::string& fileSalt, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(KEY_LEN);
    PKCS5_PBKDF2_HMAC(fileSalt.c_str(), static_cast<int>(fileSalt.size()), salt.data(), static_cast<int>(salt.size()), PBKDF2_ITERS, EVP_sha256(), static_cast<int>(key.size()), key.data());
    return key;
}

std::vector<uint8_t> KeyManager::generateSalt(const size_t len) {
    std::vector<uint8_t> salt(len);
    RAND_bytes(salt.data(), static_cast<int>(salt.size()));
    return salt;
}

std::string& KeyManager::getMasterKeyFile() {
    return MASTER_KEY_FILE;
}
