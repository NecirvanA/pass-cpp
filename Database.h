#pragma once

#include <sqlite3.h>
#include <sodium.h>
#include <string>
#include <optional>

class Database {
    sqlite3* db;
    unsigned char key[crypto_secretbox_KEYBYTES];

public:
    explicit Database(const std::string& masterPassword);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void addCredential(const std::string& platform, const std::string& password);
    std::optional<std::string> getCredential(const std::string& platform);

private:
    bool loadSalt(unsigned char* salt);
    void saveSalt(const unsigned char* salt);
    bool platformExists(const std::string& platform);
};