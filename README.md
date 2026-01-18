# MiniKV

I implemented a lightweight C++ key-value storage engine supporting multi-user isolation and per-user encrypted data storage, with a CLI interface and persistent backend.\
*The release version only runs on Window-64*
---

# Project Description

About the use of this project: run `MiniKV.exe` directly and see hint. Just as the picture below.\
![example.png](example.png)
This MiniKV save the data encrypts and stores data locally. Please protect the files in `saves` directory.
---

# Saving And Encrypt

The project support multiple accounts, every account have a password and two "salts" for safety saving.\
Accounts' information are encrypted and saved into `saves/users.mkv`. Everyone have an ".mkv" file with stochastic file name to save encrypted K-V pairs.\
This project uses *openssl* library to encrypt. Specifically, use **AES** to encrypt and **sha** for check if file have been tempered with. File `saves/master.key` for manage keys.\
When **sha** errors, all saves will be *deleted* for data safe.
---

# Limitations And Shortcomings

 - Data saving may fail when information too much.
 - User manage is not available.
 - Encryption may be vulnerable to attack when files leak.
 - Data is extremely fragile, and files that have been tampered with will be permanently lost.
---

# Configuration

cmake minimum required: V3.25
cmake standard: C++ 20
MinGW version: 14.0 w64
cmake exe linker flags: static
The release version only runs on Window-64
Open Source License: [MIT LICENSE](LICENSE)
