#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

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

int main() {
    initializeWinsock();

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

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

    send(sock, (char*)&choice, sizeof(choice), 0);

    char serverResponse[BUF_SIZE];
    ZeroMemory(serverResponse, BUF_SIZE);
    recv(sock, serverResponse, BUF_SIZE, 0);
    std::cout << "Server says: " << serverResponse << std::endl;

    if (choice == 1 || choice == 2) {
        std::cout << "Enter username: ";
        std::string username;
        std::cin >> username;
        std::cout << "Enter password: ";
        std::string password;
        std::cin >> password;

        std::string credentials = username + ":" + password;
        send(sock, credentials.c_str(), credentials.length() + 1, 0);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
