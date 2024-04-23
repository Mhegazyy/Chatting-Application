#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <thread>
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
        capacity = 2; // Initial capacity of 2
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
    std::string line, usr, pwd;
    while (getline(file, line)) {
        std::istringstream iss(line);
        if (getline(iss, usr, ':') && getline(iss, pwd)) {
            if (usr == username && pwd == hashPassword(password)) {
                return true;
            }
        }
    }
    return false;
}

void handleClient(SOCKET clientSocket) {
    char buf[BUF_SIZE];
    ZeroMemory(buf, BUF_SIZE);
    int bytesReceived = recv(clientSocket, buf, BUF_SIZE, 0);  // Receive the choice
    if (bytesReceived > 0) {
        int choice = atoi(buf);  // Convert received data to int (choice)
        std::string response = (choice == 1) ? "Login selected." : "Registration selected.";
        send(clientSocket, response.c_str(), response.length() + 1, 0);  // Send response to client

        // Wait for username and password
        ZeroMemory(buf, BUF_SIZE);
        bytesReceived = recv(clientSocket, buf, BUF_SIZE, 0);
        if (bytesReceived > 0) {
            std::string credentials(buf);
            auto colonPos = credentials.find(":");
            std::string username = credentials.substr(0, colonPos);
            std::string password = credentials.substr(colonPos + 1);
            std::string hashedPassword = hashPassword(password);

            if (choice == 1) { // Login
                if (verifyUserCredentials(username, hashedPassword)) {
                    response = "Login successful!";
                }
                else {
                    response = "Login failed!";
                }
            }
            else { // Registration
                storeUserCredentials(username, hashedPassword);
                response = "Registration successful!";
            }
            send(clientSocket, response.c_str(), response.length() + 1, 0);  // Send final response
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

    while (clientSockets.getSize() < 2) {
        SOCKET clientSocket = accept(listeningSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to accept connection: " << WSAGetLastError() << std::endl;
            continue;
        }
        std::lock_guard<std::mutex> lock(clientMutex);
        clientSockets.add(clientSocket);
        std::thread clientThread(handleClient, clientSocket);
        clientThread.detach();
    }

    closesocket(listeningSocket);
    WSACleanup();
    return 0;
}
