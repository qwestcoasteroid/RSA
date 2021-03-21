#include <Windows.h>

#include <iostream>
#include <clocale>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <cwctype>

#include "rsa_cipher.h"

std::vector<std::vector<uint32_t>> messages;

enum class Commands { kUndefined, kExit, kEncrypt, kDecrypt, kList };

std::map<std::wstring, Commands> commands{
    { L"exit",      Commands::kExit },
    { L"encrypt",   Commands::kEncrypt },
    { L"decrypt",   Commands::kDecrypt },
    { L"list",      Commands::kList }
};

std::wostream& operator<<(std::wostream& __stream,
    const std::vector<uint32_t>& __vector) {
    
    for (auto i : __vector) {
        __stream << i << L' ';
    }

    return __stream;
}

int main() {

    std::setlocale(LC_ALL, "Rus");

    SetConsoleCP(1251);

    RsaCipher rsa;

    std::wstring command, message;
    uint32_t index{};

    while (command != L"exit") {
        std::wcout << L"Введите команду: ";
        std::wcin >> command;

        switch (commands[command]) {
        case Commands::kExit:
            break;
        case Commands::kEncrypt:
            std::wcin.ignore();
            std::getline(std::wcin, message);
            std::transform(message.begin(), message.end(), message.begin(),
                [](auto __char) { return std::towlower(__char); });
            std::wcout << L"Зашифрованное сообщение: ";
            std::wcout << messages.emplace_back(rsa.Encrypt(message));
            std::wcout << std::endl;
            break;
        case Commands::kDecrypt:
            std::wcin >> index;
            std::wcout << L"Расшифрованное сообщение: ";
            std::wcout << rsa.Decrypt(messages[index]) << std::endl;
            break;
        case Commands::kList:
            for (size_t i = 0; i < messages.size(); ++i) {
                std::wcout << L"(" << i << L") ";
                std::wcout << messages[i] << std::endl;
            }
            break;
        default:
            std::wcout << L"Неизвестная команда" << std::endl;
        }
    }
    
    return 0;
}