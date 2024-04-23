//Server.cpp
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <thread>
#include <vector>
#include <algorithm>
#include <cctype>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

class SocketArray {
private:
    std::vector<SOCKET> sockets;
    std::mutex mutex;

public:
    void add(SOCKET socket) {
        std::lock_guard<std::mutex> lock(mutex);
        sockets.push_back(socket);
    }

    void remove(SOCKET socket) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = std::find(sockets.begin(), sockets.end(), socket);
        if (it != sockets.end()) {
            sockets.erase(it);
        }
    }

    void broadcast(const std::string& message, SOCKET sender) {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto sock : sockets) {
            if (sock != sender) {  // Send the message to all clients except the sender
                send(sock, message.c_str(), message.length(), 0);
            }
        }
    }

    size_t getSize() const {
        return sockets.size();
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

std::string encryptPassword(const std::string& password) {
    std::string encryptedPassword = password;
    for (char& c : encryptedPassword) {
        if (isalpha(c)) {
            c = ((c - 'a' + 3) % 26) + 'a'; // Shift by 3 positions
        }
    }
    return encryptedPassword;
}

std::string decryptPassword(const std::string& encryptedPassword) {
    std::string decryptedPassword = encryptedPassword;
    for (char& c : decryptedPassword) {
        if (isalpha(c)) {
            c = ((c - 'a' - 3 + 26) % 26) + 'a'; // Shift back by 3 positions
        }
    }
    return decryptedPassword;
}

void storeUserCredentials(const std::string& username, const std::string& encryptedPassword) {
    std::ofstream file("Users.txt", std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt for writing" << std::endl;
        return;
    }

    file << username << ":" << encryptedPassword << std::endl;
    file.close();
}

bool verifyUserCredentials(const std::string& username, const std::string& password) {
    std::ifstream file("Users.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt" << std::endl;
        return false;
    }

    std::string line, usr, encPwd;
    while (getline(file, line)) {
        std::istringstream iss(line);
        if (getline(iss, usr, ':') && getline(iss, encPwd)) {
            if (usr == username && decryptPassword(encPwd) == password) {
                return true;
            }
        }
    }
    return false;
}

void handleClient(SOCKET clientSocket) {
    clientSockets.add(clientSocket);

    char buf[BUF_SIZE];
    int bytesReceived;
    while ((bytesReceived = recv(clientSocket, buf, BUF_SIZE - 1, 0)) > 0) {
        buf[bytesReceived] = '\0';  // Null terminate the received data

        std::string input(buf);
        if (input.substr(0, 5) == "login" || input.substr(0, 8) == "register") {
            // Handle login or registration
            size_t colonPos = input.find(":");
            if (colonPos != std::string::npos) {
                std::string username = input.substr(6, colonPos - 6);
                std::string password = input.substr(colonPos + 1);

                if (input.substr(0, 5) == "login" && verifyUserCredentials(username, password)) {
                    send(clientSocket, "Login successful!", 17, 0);
                }
                else if (input.substr(0, 8) == "register") {
                    std::string encryptedPassword = encryptPassword(password);
                    storeUserCredentials(username, encryptedPassword);
                    send(clientSocket, "Registration successful!", 24, 0);
                }
                else {
                    send(clientSocket, "Login failed!", 13, 0);
                }
            }
        }
        else {
            // Broadcast the message to other clients
            clientSockets.broadcast(input, clientSocket);
        }
    }

    if (bytesReceived <= 0) {
        if (bytesReceived == 0) {
            std::cout << "Connection closed by client." << std::endl;
        }
        else {
            std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
        }
        closesocket(clientSocket);
        clientSockets.remove(clientSocket);
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

        std::thread(handleClient, clientSocket).detach();  // Corrected line here
    }

    closesocket(listeningSocket);
    WSACleanup();
    return 0;
}

