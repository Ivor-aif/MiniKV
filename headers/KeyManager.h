//
// Created by Ivor_Aif on 2026/1/11.
//

#ifndef KEYMANAGER_H
#define KEYMANAGER_H

#include <string>
#include <vector>
#include <random>
#include <fstream>
#include <openssl/rand.h>

#include "Persistence.h"

class KeyManager {
private:
public:
    static std::vector<std::uint8_t> loadOrCreateMasterKey();
    static std::vector<std::uint8_t> deriveUserKey(const std::string& fileSalt, const std::vector<std::uint8_t>& salt);
    static std::vector<std::uint8_t> generateSalt(size_t len = 16);
    static std::string& getMasterKeyFile();
};

#endif // KEYMANAGER_H
