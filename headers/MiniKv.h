//
// Created by Ivor_Aif on 2026/1/12.
//

#ifndef MINIKV_H
#define MINIKV_H

#include <unordered_map>

#include "User.h"
#include "Persistence.h"
#include "KeyManager.h"

class MiniKv {
private:
    User& user;
    std::unordered_map<std::string, std::string> kvs;
    void load();
    void edit();
public:
    explicit MiniKv(User& user);
    ~MiniKv();
    bool put(const std::string& key, const std::string& value);
    bool modify(const std::string& key, const std::string& value);
    std::string get(const std::string& key);
    bool del(const std::string& key);
    void clear();
    std::vector<std::string> skim() const;
};

#endif // MINIKV_H
