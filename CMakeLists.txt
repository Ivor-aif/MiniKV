cmake_minimum_required(VERSION 3.31)
project(MiniKV)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXE_LINKER_FLAGS "-static")
link_libraries(crypto ws2_32 crypt32 bcrypt advapi32)

add_executable(MiniKV
        .idea/.gitignore
        .idea/MiniKV.iml
        .idea/modules.xml
        .idea/workspace.xml
        .gitignore
        LICENSE
        main.cpp
        sources/User.cpp
        headers/User.h
        sources/Persistence.cpp
        headers/Persistence.h
        sources/KeyManager.cpp
        headers/KeyManager.h
        sources/MiniKv.cpp
        headers/MiniKv.h
)
