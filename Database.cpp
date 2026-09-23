#include "Database.h"

#include <vector>
#include <stdexcept>
#include <cstring>

Database::Database(const std::string& masterPassword) {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }

    if (sqlite3_open("store.db", &db) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }

    const char* setup =
        "CREATE TABLE IF NOT EXISTS credentials ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "platform TEXT NOT NULL,"
        "ciphertext BLOB NOT NULL,"
        "nonce BLOB NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS meta ("
        "key TEXT PRIMARY KEY,"
        "value BLOB"
        ");";

    char* errMsg = nullptr;
    if (sqlite3_exec(db, setup, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::string err = errMsg;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        throw std::runtime_error(err);
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    if (!loadSalt(salt)) {
        randombytes_buf(salt, sizeof salt);
        saveSalt(salt);
    }

    if (crypto_pwhash(key, sizeof key,
                       masterPassword.c_str(), masterPassword.size(),
                       salt,
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sqlite3_close(db);
        throw std::runtime_error("Key derivation failed (out of memory?)");
    }
}

Database::~Database() {
    sodium_memzero(key, sizeof key);
    sqlite3_close(db);
}

bool Database::platformExists(const std::string& platform) {
    const char* sql = "SELECT 1 FROM credentials WHERE platform = ? LIMIT 1;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }

    sqlite3_bind_text(stmt, 1, platform.c_str(), -1, SQLITE_TRANSIENT);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

void Database::addCredential(const std::string& platform, const std::string& password) {
    if (platformExists(platform)) {
        throw std::runtime_error("An entry for '" + platform + "' already exists");
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> ciphertext(password.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(),
                           reinterpret_cast<const unsigned char*>(password.data()),
                           password.size(), nonce, key);

    const char* sql = "INSERT INTO credentials (platform, ciphertext, nonce) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }

    sqlite3_bind_text(stmt, 1, platform.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, ciphertext.data(), static_cast<int>(ciphertext.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, nonce, sizeof nonce, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error(sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
}

std::optional<std::string> Database::getCredential(const std::string& platform) {
    const char* sql = "SELECT ciphertext, nonce FROM credentials WHERE platform = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }

    sqlite3_bind_text(stmt, 1, platform.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<std::string> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* ctext = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 0));
        int ctextLen = sqlite3_column_bytes(stmt, 0);
        const unsigned char* nonce = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 1));

        std::vector<unsigned char> decrypted(ctextLen - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(decrypted.data(), ctext, ctextLen, nonce, key) != 0) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("Decryption failed - wrong master password or corrupted data");
        }

        result = std::string(decrypted.begin(), decrypted.end());
    }

    sqlite3_finalize(stmt);
    return result;
}

bool Database::loadSalt(unsigned char* salt) {
    const char* sql = "SELECT value FROM meta WHERE key = 'salt';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::memcpy(salt, sqlite3_column_blob(stmt, 0), crypto_pwhash_SALTBYTES);
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

void Database::saveSalt(const unsigned char* salt) {
    const char* sql = "INSERT INTO meta (key, value) VALUES ('salt', ?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_blob(stmt, 1, salt, crypto_pwhash_SALTBYTES, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}