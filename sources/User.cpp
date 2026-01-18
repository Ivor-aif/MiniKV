//
// Created by Ivor_Aif on 2026/1/8.
//

#include "../headers/User.h"

User::User(std::string username, const std::string& password) : username(std::move(username)) {
    const std::string chars = "qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis1(0, static_cast<int>(chars.length()) - 1);
    this->salts.first = "";
    this->salts.second = "";
    for (int i = 0; i < 16; i++) {
        this->salts.first += chars[dis1(gen)];
        this->salts.second += chars[dis1(gen)];
    }
    this->passwordHash = sha256(password + this->salts.first);
    std::uniform_int_distribution<int> dis2(0, 5);
    int fnl = 10 + dis2(gen);
    this->filename = "";
    for (int i = 0; i < fnl; i++) {
        this->filename += chars[dis1(gen)];
    }
    this->filename += ".mkv";
}

User::~User() = default;

std::string User::u2s() const {
    std::string out;
    out.reserve(this->username.size() + this->passwordHash.size() + this->salts.first.size() + this->filename.size() + 16);
    auto write = [&out](const std::string& str) {
        const uint32_t len = str.size();
        out.push_back(static_cast<int8_t>(len >> 24 & 0xff));
        out.push_back(static_cast<int8_t>(len >> 16 & 0xff));
        out.push_back(static_cast<int8_t>(len >> 8 & 0xff));
        out.push_back(static_cast<int8_t>(len & 0xff));
        out.append(str);
    };
    write(this->username);
    write(this->passwordHash);
    write(this->salts.first);
    write(this->salts.second);
    write(this->filename);
    return out;
}

User::User(std::string& str) {
    size_t offset = 0;
    auto read = [&offset, &str](std::string& target) {
        if (offset + 4 > str.size()) {
            throw std::out_of_range("Data too short for length header");
        }
        const uint32_t len = static_cast<unsigned char>(str[offset]) << 24 | static_cast<unsigned char>(str[offset + 1]) << 16 | static_cast<unsigned char>(str[offset + 2]) << 8 | static_cast<unsigned char>(str[offset + 3]);
        offset += 4;
        if (offset + len > str.size()) {
            throw std::out_of_range("Data too short for content");
        }
        target.assign(str.data() + offset, len);
        offset += len;
    };
    read(this->username);
    read(this->passwordHash);
    read(this->salts.first);
    read(this->salts.second);
    read(this->filename);
}

std::string User::sha256(const std::string& saltedPwd) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(saltedPwd.c_str()), saltedPwd.size(), hash);
    std::stringstream ss;
    for (const unsigned char i: hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
    }
    return ss.str();
}

bool User::verifyPassword(const std::string& password) const {
    return User::sha256(password + this->salts.first) == this->passwordHash;
}

std::optional<User> User::login(const std::string& username, const std::string& password) {
    std::vector<User> users = Persistence::load();
    if (users.empty()) {
        std::cerr << "No users' account information, please register first." << std::endl;
        return std::nullopt;
    }
    const auto it = std::ranges::find_if(users, [&username](const User& user) {
        return user.username == username;
    });
    if (it == users.end()) {
        std::cout << "No such user" << username << ", please register first." << std::endl;
        return std::nullopt;
    }
    if (sha256(password + it->salts.first) != it->passwordHash) {
        std::cout << "Wrong password." << std::endl;
        return std::nullopt;
    }
    return *it;
}

const std::string& User::getFilename() {
    return this->filename;
}

const std::string& User::getFileSalt() const {
    return this->salts.second;
}

const std::string& User::getUsername() const {
    return this->username;
}
