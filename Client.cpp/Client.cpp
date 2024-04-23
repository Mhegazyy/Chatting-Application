#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

const int BUF_SIZE = 512;

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        exit(1);
    }
}

std::string caesarEncrypt(const std::string& text, int shift) {
    std::string result;
    for (char c : text) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = static_cast<char>((c - base + shift + 26) % 26 + base);
        }
        result += c;
    }
    return result;
}

std::string caesarDecrypt(const std::string& text, int shift) {
    return caesarEncrypt(text, -shift);  // Decrypting is the reverse operation of encrypting
}

bool authenticateUser(SOCKET sock) {
    std::cout << "1: Login\n";
    std::cout << "2: Register\n";
    std::cout << "Enter your choice: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore();  // Ignore newline after entering choice
    std::string choice_str = std::to_string(choice);
    std::string encryptedChoice = caesarEncrypt(choice_str, 3);
    send(sock, encryptedChoice.c_str(), encryptedChoice.length(), 0);

    std::cout << "Enter username: ";
    std::string username;
    std::getline(std::cin, username);
    std::cout << "Enter password: ";
    std::string password;
    std::getline(std::cin, password);

    std::string credentials = username + ":" + password;
    std::string encryptedCredentials = caesarEncrypt(credentials, 3);
    send(sock, encryptedCredentials.c_str(), encryptedCredentials.length(), 0);

    char serverResponse[BUF_SIZE];
    ZeroMemory(serverResponse, BUF_SIZE);
    int bytesReceived = recv(sock, serverResponse, BUF_SIZE - 1, 0);
    if (bytesReceived > 0) {
        serverResponse[bytesReceived] = '\0';
        std::string decryptedResponse = caesarDecrypt(std::string(serverResponse), 3);
        std::cout << "Server says: " << decryptedResponse << std::endl;
        return decryptedResponse.find("successful") != std::string::npos;
    }

    return false;
}

void handleUserInput(SOCKET sock) {
    std::string userInput;
    while (true) {
        std::getline(std::cin, userInput);
        if (!userInput.empty()) {
            std::string encryptedInput = caesarEncrypt(userInput, 3);
            send(sock, encryptedInput.c_str(), encryptedInput.length(), 0);
        }
    }
}


void receiveMessages(SOCKET sock) {
    char buf[BUF_SIZE];
    while (true) {
        ZeroMemory(buf, BUF_SIZE);
        int bytesReceived = recv(sock, buf, BUF_SIZE - 1, 0);
        if (bytesReceived > 0) {
            buf[bytesReceived] = '\0';
            std::string decryptedMessage = caesarDecrypt(std::string(buf), 3);
            std::cout << "Server: " << decryptedMessage << std::endl;
        }
        else {
            std::cerr << "Connection closed or error occurred." << std::endl;
            break;
        }
    }
}

int main() {
    initializeWinsock();

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &hint.sin_addr);

    int connResult = connect(sock, (sockaddr*)&hint, sizeof(hint));
    if (connResult == SOCKET_ERROR) {
        std::cerr << "Can't connect to server, error: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to server.\n";
    if (!authenticateUser(sock)) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::thread receiveThread(receiveMessages, sock);
    receiveThread.detach();

    // Handle user input for chat
    handleUserInput(sock);

    closesocket(sock);
    WSACleanup();
    return 0;
}

