#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

class SocketArray {
private:
    SOCKET* sockets;
    size_t capacity;
    size_t size;

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
    SocketArray() : sockets(nullptr), capacity(0), size(0) {
        capacity = 2;
        sockets = new SOCKET[capacity];
    }

    ~SocketArray() {
        delete[] sockets;
    }

    void add(SOCKET socket) {
        if (size >= capacity) {
            resize();
        }
        sockets[size++] = socket;
    }

    SOCKET& operator[](size_t index) {
        if (index >= size) {
            throw std::out_of_range("Index out of range");
        }
        return sockets[index];
    }

    size_t getSize() const {
        return size;
    }

    bool isFull() const {
        return size == 2;
    }
};

const int BUF_SIZE = 512;
std::mutex clientMutex;
SocketArray clientSockets;

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        exit(1);
    }
}

std::string hashPassword(const std::string& password) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    EVP_DigestUpdate(context, password.c_str(), password.length());
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    EVP_MD_CTX_free(context);
    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << (int)hash[i];
    }
    return ss.str();
}

void storeUserCredentials(const std::string& username, const std::string& hashedPassword) {
    std::ofstream file("Users.txt", std::ios::app);
    if (file.is_open()) {
        file << username << ":" << hashedPassword << std::endl;
        file.close();
    }
}

bool verifyUserCredentials(const std::string& username, const std::string& password) {
    std::ifstream file("Users.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt" << std::endl;
        return false;
    }

    std::string line, usr, pwd;
    bool userFound = false;
    while (getline(file, line)) {
        std::istringstream iss(line);
        if (getline(iss, usr, ':') && getline(iss, pwd)) {
            if (usr == username) {
                userFound = true;
                std::cout << "Retrieved hashed password: " << pwd << std::endl;
                std::string hashedPassword = hashPassword(password);
                std::cout << "Hashed password entered by user: " << hashedPassword << std::endl;
                if (pwd == hashedPassword) {
                    return true; // User found and password matches
                }
                else {
                    return false; // Password doesn't match
                }
            }
        }
    }

    // If the loop completes without finding the username
    if (!userFound) {
        std::cout << "User not found: " << username << std::endl;
        return false;
    }

    // This code should not be reached, but return false to handle unexpected cases
    return false;
}



void handleClient(SOCKET clientSocket) {
    char buf[BUF_SIZE];
    recv(clientSocket, buf, BUF_SIZE, 0); // Receive choice: Login or Register
    int choice = atoi(buf);

    if (choice == 1) { // Login
        recv(clientSocket, buf, BUF_SIZE, 0); // Receive username:password
        std::string credentials(buf);
        auto colonPos = credentials.find(":");
        std::string username = credentials.substr(0, colonPos);
        std::string password = credentials.substr(colonPos + 1);
        if (verifyUserCredentials(username, password)) {
            const char* msg = "Login successful!";
            send(clientSocket, msg, strlen(msg), 0);
        }
        else {
            const char* msg = "Login failed!";
            send(clientSocket, msg, strlen(msg), 0);
            closesocket(clientSocket);
            return;
        }
    }
    else if (choice == 2) { // Register
        recv(clientSocket, buf, BUF_SIZE, 0); // Receive username:password
        std::string credentials(buf);
        auto colonPos = credentials.find(":");
        std::string username = credentials.substr(0, colonPos);
        std::string password = credentials.substr(colonPos + 1);
        storeUserCredentials(username, hashPassword(password));
        const char* msg = "Registration successful!";
        send(clientSocket, msg, strlen(msg), 0);
    }

    // After successful login or registration, handle chat
    while (true) {
        ZeroMemory(buf, BUF_SIZE);
        int bytesReceived = recv(clientSocket, buf, BUF_SIZE, 0);
        if (bytesReceived <= 0) {
            break;  // Client has disconnected or an error occurred
        }

        std::string message(buf);
        // Forward message to other clients
        for (int i = 0; i < clientSockets.getSize(); i++) {
            if (clientSockets[i] != clientSocket) {
                send(clientSockets[i], message.c_str(), message.length(), 0);
            }
        }
    }
    closesocket(clientSocket);
}

int main() {
    initializeWinsock();

    SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = INADDR_ANY;

    bind(listeningSocket, (sockaddr*)&server, sizeof(server));
    listen(listeningSocket, 2);

    while (true) {
        SOCKET clientSocket = accept(listeningSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to accept connection: " << WSAGetLastError() << std::endl;
            continue;
        }

        std::thread clientThread(handleClient, clientSocket);
        clientThread.detach();
    }

    closesocket(listeningSocket);
    WSACleanup();
    return 0;
}

