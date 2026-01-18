//
// Created by Ivor_Aif on 2026/1/10.
//

#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <fstream>

#include "User.h"
#include "KeyManager.h"

class User;

class Persistence { // Static class
private:
    static const std::string path;
    static const std::string users;
    Persistence() = delete;
    ~Persistence() = delete;
    Persistence(const Persistence&) = delete;
    Persistence& operator=(const Persistence&) = delete;
public:
    static bool initial(bool regist = true);
    static const std::string& getPath();
    static std::vector<User> load();
    static void save(const std::vector<User>& usrs);
};

struct EncryptedBlob {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

class CryptoFile {
public:
    static EncryptedBlob encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext);
    static bool decrypt(const std::vector<uint8_t>& key, const EncryptedBlob& blob, std::vector<uint8_t>& plaintext);
};

#endif // PERSISTENCE_H
