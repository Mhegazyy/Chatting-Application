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

void receiveMessages(SOCKET sock) {
    char buf[BUF_SIZE];
    while (true) {
        ZeroMemory(buf, BUF_SIZE);
        int bytesReceived = recv(sock, buf, BUF_SIZE, 0);
        if (bytesReceived > 0) {
            std::cout << "Server: " << buf << std::endl;
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
    std::cout << "1: Login\n";
    std::cout << "2: Register\n";
    std::cout << "Enter your choice: ";

    int choice;
    std::cin >> choice;
    send(sock, std::to_string(choice).c_str(), sizeof(choice), 0);

    std::cout << "Enter username: ";
    std::string username;
    std::cin >> username;
    std::cout << "Enter password: ";
    std::string password;
    std::cin >> password;

    std::string credentials = username + ":" + password;
    send(sock, credentials.c_str(), credentials.length(), 0);

    char serverResponse[BUF_SIZE];
    ZeroMemory(serverResponse, BUF_SIZE);
    recv(sock, serverResponse, BUF_SIZE, 0);
    std::cout << "Server says: " << serverResponse << std::endl;

    std::thread receiveThread(receiveMessages, sock);
    receiveThread.detach();

    std::string userInput;
    while (true) {
        std::getline(std::cin, userInput);
        if (!userInput.empty()) {
            send(sock, userInput.c_str(), userInput.length(), 0);
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
