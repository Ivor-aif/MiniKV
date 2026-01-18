//
// Created by Ivor_Aif on 2026/1/8.
//

#ifndef USER_H
#define USER_H

#include <string>
#include <ranges>
#include <utility>
#include <random>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

#include "Persistence.h"

class User {
private:
    std::string username;
    std::string passwordHash;
    std::pair<std::string, std::string> salts; // for account-password and file, respectively
    std::string filename;
    static std::string sha256(const std::string& saltedPwd);

public:
    User(std::string username, const std::string& password); // register
    ~User();
    [[nodiscard]] bool verifyPassword(const std::string& password) const;
    [[nodiscard]] std::string u2s() const;
    explicit User(std::string& str); // s2u
    static std::optional<User> login(const std::string& username, const std::string& password);
    const std::string& getFilename();
    [[nodiscard]] const std::string& getFileSalt() const;
    [[nodiscard]] const std::string& getUsername() const;
};

#endif // USER_H
