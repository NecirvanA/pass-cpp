#include "Database.h"

#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <filesystem>
#include <termios.h>
#include <unistd.h>

std::string readPasswordHidden(const std::string& prompt) {
    std::cout << prompt;

    termios oldt{};
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << '\n';
    return password;
}

std::string setupMasterPassword() {
    bool isNewDatabase = !std::filesystem::exists("store.db");

    if (!isNewDatabase) {
        return readPasswordHidden("Enter master password: ");
    }

    std::cout << "No existing database found: set a master password.\n";
    while (true) {
        std::string pw1 = readPasswordHidden("Create master password: ");
        std::string pw2 = readPasswordHidden("Confirm master password: ");

        if (pw1 == pw2 && !pw1.empty()) {
            return pw1;
        }
        std::cout << "Passwords didn't match (or were empty) - try again.\n";
    }
}

void menu() noexcept {
    std::cout << "1. View passwords\n";
    std::cout << "2. Add password\n";
    std::cout << "3. Quit\n";
}

void getUserInput(std::string& input) {
    std::getline(std::cin, input);

    while (input != "1" && input != "2" && input != "3") {
        std::cout << "Enter a valid input!\n";
        std::getline(std::cin, input);
    }
}

void waitForUser() {
    std::string temp{};
    std::getline(std::cin, temp);
}

void addNewCredential(Database& db) {
    std::system("clear");

    std::string platform{};
    std::string password{};

    std::cout << "Enter the platform: ";
    std::getline(std::cin, platform);
    std::cout << '\n';

    password = readPasswordHidden("Enter the password: ");

    try {
        db.addCredential(platform, password);
        std::cout << "Saved.\n";
    } catch (const std::exception& e) {
        std::cout << "Failed to save: " << e.what() << '\n';
    }
}

void getCredential(Database& db) {
    std::system("clear");

    std::string platform{};

    std::cout << "Enter the platform: ";
    std::getline(std::cin, platform);
    std::cout << '\n';

    try {
        auto password = db.getCredential(platform);
        if (password.has_value()) {
            std::cout << "Password: " << password.value() << '\n';
        } else {
            std::cout << "Not found in database\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Failed to retrieve: " << e.what() << '\n';
    }
}

int main() {
    std::string masterPassword = setupMasterPassword();

    std::unique_ptr<Database> db;
    try {
        db = std::make_unique<Database>(masterPassword);
    } catch (const std::exception& e) {
        std::cout << "Failed to open database: " << e.what() << '\n';
        return 1;
    }

    std::string input{};

    while (true) {
        std::system("clear");
        menu();

        getUserInput(input);

        if (input == "1") {
            getCredential(*db);
        } else if (input == "2") {
            addNewCredential(*db);
        } else if (input == "3") {
            break;
        }

        std::cout << "Press ENTER to continue...\n";
        waitForUser();
    }
    
    std::system("clear");
    std::cout << "Goodbye.\n";
    return 0;
}