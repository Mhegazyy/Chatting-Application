#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

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

std::string encryptPassword(const std::string& password) {
    std::string encryptedPassword = password;
    for (char& c : encryptedPassword) {
        if (isalpha(c)) {
            c = ((c - 'a' + 3) % 26) + 'a'; // Shift by 3 positions (for lowercase letters)
        }
    }
    return encryptedPassword;
}

std::string decryptPassword(const std::string& encryptedPassword) {
    std::string decryptedPassword = encryptedPassword;
    for (char& c : decryptedPassword) {
        if (isalpha(c)) {
            c = ((c - 'a' - 3 + 26) % 26) + 'a'; // Shift back by 3 positions (for lowercase letters)
        }
    }
    return decryptedPassword;
}

void storeUserCredentials(const std::string& username, const std::string& encryptedPassword, const std::string& iv) {
    std::ofstream file("Users.txt", std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt for writing" << std::endl;
        return;
    }

    // Write username, encrypted password, and IV to file
    file << username << ":" << encryptedPassword << ":" << iv << std::endl;
    file.close();
}

bool verifyUserCredentials(const std::string& username, const std::string& password) {
    std::ifstream file("Users.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open Users.txt" << std::endl;
        return false;
    }

    std::string line, usr, encPwd, iv;
    bool userFound = false;
    while (getline(file, line)) {
        std::istringstream iss(line);
        if (getline(iss, usr, ':') && getline(iss, encPwd, ':') && getline(iss, iv)) {
            if (usr == username) {
                userFound = true;
                // Decrypt the stored password using the IV
                std::string decryptedPassword = decryptPassword(encPwd);
                if (password == decryptedPassword) {
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
    int bytesReceived = recv(clientSocket, buf, BUF_SIZE - 1, 0); // Receive choice: Login or Register
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving data from client" << std::endl;
        closesocket(clientSocket);
        return;
    }
    buf[bytesReceived] = '\0'; // Ensure null-termination

    int choice = atoi(buf);

    if (choice == 1) { // Login
        bytesReceived = recv(clientSocket, buf, BUF_SIZE - 1, 0); // Receive username:password
        if (bytesReceived <= 0) {
            std::cerr << "Error receiving data from client" << std::endl;
            closesocket(clientSocket);
            return;
        }
        buf[bytesReceived] = '\0'; // Ensure null-termination

        // Log the received credentials before parsing
        std::cout << "Received credentials from client: " << buf << std::endl;

        // Parse the received credentials
        std::string credentials(buf);
        auto colonPos = credentials.find(":");
        if (colonPos == std::string::npos) {
            std::cerr << "Invalid credentials format" << std::endl;
            const char* msg = "Invalid credentials format";
            send(clientSocket, msg, strlen(msg), 0);
            closesocket(clientSocket);
            return;
        }

        std::string username = credentials.substr(0, colonPos);
        std::string password = credentials.substr(colonPos + 1);

        // Verify that the received username and password are not empty
        if (username.empty() || password.empty()) {
            std::cerr << "Empty username or password" << std::endl;
            const char* msg = "Empty username or password";
            send(clientSocket, msg, strlen(msg), 0);
            closesocket(clientSocket);
            return;
        }

        // Log the parsed credentials
        std::cout << "Parsed username: " << username << std::endl;
        std::cout << "Parsed password: " << password << std::endl;

        // Verify user credentials
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
        bytesReceived = recv(clientSocket, buf, BUF_SIZE - 1, 0); // Receive username:password
        if (bytesReceived <= 0) {
            std::cerr << "Error receiving data from client" << std::endl;
            closesocket(clientSocket);
            return;
        }
        buf[bytesReceived] = '\0'; // Ensure null-termination

        std::string credentials(buf);
        auto colonPos = credentials.find(":");
        if (colonPos == std::string::npos) {
            std::cerr << "Invalid credentials format" << std::endl;
            const char* msg = "Invalid credentials format";
            send(clientSocket, msg, strlen(msg), 0);
            closesocket(clientSocket);
            return;
        }

        std::string username = credentials.substr(0, colonPos);
        std::string password = credentials.substr(colonPos + 1);

        // Encrypt the password and store it
        std::string encryptedPassword = encryptPassword(password);
        if (encryptedPassword.empty()) {
            std::cerr << "Error encrypting password" << std::endl;
            const char* msg = "Error registering user";
            send(clientSocket, msg, strlen(msg), 0);
            closesocket(clientSocket);
            return;
        }

        // Store username and encrypted password
        storeUserCredentials(username, encryptedPassword, "");

        const char* msg = "Registration successful!";
        send(clientSocket, msg, strlen(msg), 0);
    }

    // After successful login or registration, handle chat
    while (true) {
        ZeroMemory(buf, BUF_SIZE);
        bytesReceived = recv(clientSocket, buf, BUF_SIZE - 1, 0);
        if (bytesReceived <= 0) {
            break;  // Client has disconnected or an error occurred
        }
        buf[bytesReceived] = '\0'; // Ensure null-termination

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
