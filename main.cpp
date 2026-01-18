#include <conio.h>

#include "headers/KeyManager.h"
#include "headers/MiniKv.h"
#include "headers/Persistence.h"
#include "headers/User.h"

User* pCurr = nullptr;

void login();
void regist();

int main(const int argc, char* argv[]) {
    std::string cmd;
    if (argc > 1) {
        cmd = argv[1];
        std::ranges::transform(cmd, cmd.begin(), ::tolower);
    }
    if (Persistence::initial(false) && argc == 2 && cmd == "login") {
        login();
    } else {
        regist();
    }
    if (pCurr) {
        std::cout << "You can input a char to choice one operate: " << std::endl;
        std::cout << "\tK for show all the your keys." << std::endl;
        std::cout << "\tG for get your value of specific key." << std::endl;
        std::cout << "\tP for put new key-value pair." << std::endl;
        std::cout << "\tM for modify existed key's value." << std::endl;
        std::cout << "\tD for delete an exist key-value pair." << std::endl;
        std::cout << "\tC for clear all the exist key-value pair." << std::endl;
        std::cout << "\tO for logout." << std::endl;
        auto obj = MiniKv(*pCurr);
        char ch;
        while (ch = static_cast<char>(getchar())) { // Endless loop.
            switch (ch) {
                case '\r':
                case '\n':
                    break;
                case 'k':
                case 'K': {
                    std::vector<std::string> keys = obj.skim();
                    std::cout << "You have " << keys.size() << " keys: " << std::endl;
                    for (const auto &key: keys) {
                        std::cout << '\t' << key << std::endl;
                    }
                    break;
                }
                case 'g':
                case 'G': {
                    std::string key;
                    std::cout << "Please enter an existed key: ";
                    std::cin >> key;
                    std::cout << " - " << obj.get(key) << std::endl;
                    break;
                }
                case 'p':
                case 'P': {
                    std::string key, value;
                    std::cout << "Please enter a new key: ";
                    std::cin >> key;
                    std::cout << std::endl << "Please enter a value for this key: ";
                    std::cin >> value;
                    obj.put(key, value);
                    std::cout << std::endl << "Put new key-value pair successful." << std::endl;
                    break;
                }
                case 'm':
                case 'M': {
                    std::string key, value;
                    std::cout << "Please enter a new key: ";
                    std::cin >> key;
                    std::cout << std::endl << "Please enter a value for this key: ";
                    std::cin >> value;
                    obj.modify(key, value);
                    std::cout << std::endl << "Modify key-value pair successful." << std::endl;
                    break;
                }
                case 'd':
                case 'D': {
                    std::string key;
                    std::cout << "Please enter an existed key: ";
                    std::cin >> key;
                    obj.del(key);
                    std::cout << std::endl << "Delete existing key-value pair successful." << std::endl;
                    break;
                }
                case 'c':
                case 'C': {
                    std::cout << "Are you sure to clear all your data? [Y/y] for continue delete.";
                    std::cin >> ch;
                    if (ch == 'y' || ch == 'Y') {
                        obj.clear();
                        std::cout << std::endl << "Clear successful." << std::endl;
                    } else {
                        std::cout << std::endl << "Cancelled." << std::endl;
                    }
                    break;
                }
                case 'o':
                case 'O': {
                    std::cout << "Logout successful, process will exit soon. Welcome to use again." << std::endl;
                    goto finish;
                    break;
                }
                default:
                    std::cout << "Invalid input." << std::endl;
            }
        }
    }
    finish:delete pCurr;
    pCurr = nullptr;
    return 0;
}

void login() {
    std::cout << "Login ..." << std::endl;
    std::cout << "Enter Username: ";
    std::string username;
    std::cin >> username;
    std::cout << "Enter Password: ";
    std::string password;
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r') {
        if (ch == '\b' && !password.empty()) {
            password.pop_back();
            std::cout << "\b \b";
        } else {
            password.push_back(ch);
            std::cout << "*";
        }
    }
    std::cout << std::endl;
    std::vector<User> users = Persistence::load();
    if (users.empty()) {
        std::cerr << "No users' account information, please register first." << std::endl;
        return;
    }
    const auto it = std::ranges::find_if(users, [&username](const User& user) {
        return user.getUsername() == username;
    });
    if (it == users.end()) {
        std::cout << "No such user " << username << ", please register first." << std::endl;
        return;
    }
    if (it->verifyPassword(password)) {
        pCurr = new User(*it);
        std::cout << "Login successful." << std::endl;
    } else {
        std::cout << "Login failed: wrong password." << std::endl;
    }
    password.clear();
}

void regist() {
    std::cout << "Register ..." << std::endl;
    std::cout << "Enter Username: ";
    std::string username;
    std::cin >> username;
    std::cout << "Enter Password: ";
    std::string password;
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r') {
        if (ch == '\b' && !password.empty()) {
            password.pop_back();
            std::cout << "\b \b";
        } else {
            password.push_back(ch);
            std::cout << "*";
        }
    }
    std::cout << std::endl;
    if (std::vector<User> users = Persistence::load(); std::ranges::find_if(users, [&username](const User& user) {
            return user.getUsername() == username;
        }) != users.end()) {
        std::cout << "Register fail: user name " << username << " already exists." << std::endl;
        return;
    }
    std::vector<User> users = Persistence::load();
    users.emplace_back(username, password);
    Persistence::save(users);
    std::cout << "Register successful. Run `MiniKV login` to continue." << std::endl;
}
