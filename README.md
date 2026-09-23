# pass_cpp
A lightweight password manager for linux/macOS.

## Requirements
- A C++17-capable compiler (`g++` recommended)
- [SQLite3](https://www.sqlite.org/) development library
- [libsodium](https://libsodium.org/) development library

### Installing dependencies
**Arch Linux**
```bash
sudo pacman -S sqlite libsodium
```

**Debian/Ubuntu**
```bash
sudo apt-get install libsqlite3-dev libsodium-dev
```

**macOS (Homebrew)**
```bash
brew install sqlite libsodium
```

## Building

```bash
g++ main.cpp Database.cpp -lsqlite3 -lsodium -o main
```