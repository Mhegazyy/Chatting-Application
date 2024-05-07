//Server.cpp
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <thread>
#include <algorithm>
#include <cctype>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <ctime>

#pragma comment(lib, "Ws2_32.lib")

std::mutex clientMutex;

class StringArray {
private:
    std::string* messages;
    size_t capacity;
    size_t size;

    void resize() {
        size_t newCapacity = capacity == 0 ? 2 : capacity * 2;
        std::string* newMessages = new std::string[newCapacity];
        for (size_t i = 0; i < size; ++i) {
            newMessages[i] = std::move(messages[i]);
        }
        delete[] messages;
        messages = newMessages;
        capacity = newCapacity;
    }

public:
    StringArray() : messages(nullptr), capacity(0), size(0) {}

    ~StringArray() {
        delete[] messages;
    }

    void add(const std::string& message) {
        if (size >= capacity) {
            resize();
        }
        messages[size++] = message;
    }

    size_t getSize() const {
        return size;
    }

    const std::string& operator[](size_t index) const {
        return messages[index];
    }
};

class SocketArray {
private:
    SOCKET* sockets;
    size_t capacity;
    size_t size;
    std::mutex mutex;

    void resize() {
        size_t newCapacity = capacity * 2;
        SOCKET* newSockets = new SOCKET[newCapacity];
        for (size_t i = 0; i < size; ++i) {
            newSockets[i] = sockets[i];
        }
        delete[] sockets;
        sockets = newSockets;
        capacity = newCapacity;
    }

public:
    SocketArray() : sockets(nullptr), capacity(0), size(0) {}

    ~SocketArray() {
        delete[] sockets;
    }

    void add(SOCKET socket) {
        std::lock_guard<std::mutex> lock(mutex);
        if (size >= capacity) {
            resize();
        }
        sockets[size++] = socket;
    }

    void remove(SOCKET socket) {
        std::lock_guard<std::mutex> lock(mutex);
        for (size_t i = 0; i < size; ++i) {
            if (sockets[i] == socket) {
                for (size_t j = i; j < size - 1; ++j) {
                    sockets[j] = sockets[j + 1];
                }
                --size;
                return;
            }
        }
    }

    void broadcast(const std::string& message, SOCKET sender) {
        std::lock_guard<std::mutex> lock(mutex);
        for (size_t i = 0; i < size; ++i) {
            if (sockets[i] != sender) {
                send(sockets[i], message.c_str(), message.length(), 0);
            }
        }
    }

    size_t getSize() const {
        return size;
    }
};

const int BUF_SIZE = 512;
SocketArray clientSockets;




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
    return caesarEncrypt(text, -shift);
}

void broadcastSystemMessage(const std::string& message) {
    std::string encryptedMessage = caesarEncrypt(message, 3);
    clientSockets.broadcast(encryptedMessage, INVALID_SOCKET); // INVALID_SOCKET means send to all without exception
}

void storeUserCredentials(const std::string& username, const std::string& encryptedPassword) {
    std::ofstream file("Users.txt", std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt for writing." << std::endl;
        return;
    }
    file << username << ":" << encryptedPassword << std::endl;
    file.close();
}

bool verifyUserCredentials(const std::string& username, const std::string& password) {
    std::ifstream file("Users.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt." << std::endl;
        return false;
    }
    std::string line, usr, encPwd;
    while (getline(file, line)) {
        std::istringstream iss(line);
        if (getline(iss, usr, ':') && getline(iss, encPwd)) {
            if (usr == username && caesarDecrypt(encPwd,3) == password) {
                return true;
            }
        }
    }
    return false;
}

StringArray chatMessages;

void logMessage(const std::string& message) {
    std::lock_guard<std::mutex> guard(clientMutex);
    chatMessages.add(message);
}

void saveChatHistory() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm = {};
    localtime_s(&now_tm, &now_time); // Safe conversion to local time

    std::stringstream filename;
    filename << "chat_history_";
    filename << (now_tm.tm_year + 1900) << '-';
    filename << (now_tm.tm_mon + 1) << '-';
    filename << now_tm.tm_mday << '_';
    filename << now_tm.tm_hour << '-';
    filename << now_tm.tm_min << '-';
    filename << now_tm.tm_sec << ".txt";

    std::ofstream file(filename.str());
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing chat history." << std::endl;
        return;
    }

    // Encrypt each message with Caesar cipher before writing to the file
    for (size_t i = 0; i < chatMessages.getSize(); ++i) {
        std::string encryptedMessage = caesarEncrypt(chatMessages[i], 3);
        file << encryptedMessage << std::endl;
    }
    file.close();
}

void handleDisconnect(SOCKET clientSocket) {
    clientSockets.remove(clientSocket);
    closesocket(clientSocket);
    std::cout << "Client disconnected. Active clients: " << clientSockets.getSize() << std::endl;

    // Check if active clients are less than 2 and broadcast a system message
    if (clientSockets.getSize() < 2) {
        std::string message = "Waiting for more connections to resume chatting.";
        broadcastSystemMessage(message);
    }
}

void handleClient(SOCKET clientSocket) {
    clientSockets.add(clientSocket);
    std::cout << "Client connected, socket added." << std::endl;

    char buf[BUF_SIZE];
    int bytesReceived;
    bool isLoggedIn = false;
    bool isExpectingCredentials = false;
    std::string command;

    while ((bytesReceived = recv(clientSocket, buf, BUF_SIZE - 1, 0)) > 0) {
        buf[bytesReceived] = '\0';
        std::string decryptedMessage = caesarDecrypt(std::string(buf), 3);
        logMessage(decryptedMessage);
        std::cout << "Received and decrypted message: " << decryptedMessage << std::endl;

        if (!isExpectingCredentials) {
            command = decryptedMessage;
            if (command == "1" || command == "2") {
                isExpectingCredentials = true;
                std::cout << "Command received, expecting credentials next." << std::endl;
            }
        }
        else {
            size_t colonPos = decryptedMessage.find(':');
            if (colonPos != std::string::npos) {
                std::string username = decryptedMessage.substr(0, colonPos);
                std::string password = decryptedMessage.substr(colonPos + 1);
                std::cout << "Credentials received for user: " << username << std::endl;

                if (command == "1") {  // Login
                    if (verifyUserCredentials(username, password)) {
                        isLoggedIn = true;
                        std::string response = "Login successful!";
                        std::string encryptedResponse = caesarEncrypt(response, 3);
                        send(clientSocket, encryptedResponse.c_str(), encryptedResponse.length(), 0);
                        std::cout << "Login successful for " << username << std::endl;
                    }
                    else {
                        std::string response = "Login failed!";
                        std::string encryptedResponse = caesarEncrypt(response, 3);
                        send(clientSocket, encryptedResponse.c_str(), encryptedResponse.length(), 0);
                        std::cout << "Login failed for " << username << std::endl;
                    }
                }
                else if (command == "2") {  // Registration
                    // Assume we always allow registration for simplicity
                    std::string encryptedPassword = caesarEncrypt(password, 3);
                    storeUserCredentials(username, encryptedPassword);
                    isLoggedIn = true;  // Optionally set the user as logged in immediately after registration
                    std::string response = "Registration successful!";
                    std::string encryptedResponse = caesarEncrypt(response, 3);
                    send(clientSocket, encryptedResponse.c_str(), encryptedResponse.length(), 0);
                    std::cout << "Registration successful for " << username << std::endl;
                }
                isExpectingCredentials = false;
            }
        }
        if (isLoggedIn && clientSockets.getSize() >= 2) {
            std::string encryptedMessage = caesarEncrypt(decryptedMessage, 3);
            saveChatHistory();
            clientSockets.broadcast(encryptedMessage, clientSocket);
            std::cout << "Broadcasting message." << std::endl;
        }
    }

    if (bytesReceived <= 0) {
        std::cout << "Client disconnected or receive error." << std::endl;
        handleDisconnect(clientSocket);
    }
}


int main() {
    initializeWinsock();
    SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = INADDR_ANY;

    if (bind(listeningSocket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening..." << std::endl;
    while (true) {
        SOCKET clientSocket = accept(listeningSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
            continue;
        }
        std::thread clientThread(handleClient, clientSocket);
        clientThread.detach();
    }

    closesocket(listeningSocket);
    WSACleanup();
    return 0;
}
