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

    // Create a socket for the server
    SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listeningSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Bind the socket to an IP address and port
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(54000);  // Port number
    server.sin_addr.s_addr = INADDR_ANY;

    if (bind(listeningSocket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    // Listen on the socket for connections
    listen(listeningSocket, 2);

    // Main loop to accept incoming connections
    while (true) {
        sockaddr_in client;
        int clientSize = sizeof(client);

        SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&client, &clientSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to accept connection: " << WSAGetLastError() << std::endl;
            continue; // Continue to the next iteration of the loop
        }

        // Display the IP address of the client
        char clientIP[NI_MAXHOST];
        ZeroMemory(clientIP, NI_MAXHOST);
        inet_ntop(AF_INET, &client.sin_addr, clientIP, NI_MAXHOST);
        std::cout << "Client connected: " << clientIP << std::endl;

        // Echo back messages to the client
        char buf[BUF_SIZE];
        while (true) {
            ZeroMemory(buf, BUF_SIZE);
            int bytesReceived = recv(clientSocket, buf, BUF_SIZE, 0);
            if (bytesReceived == SOCKET_ERROR) {
                std::cerr << "Error in recv(): " << WSAGetLastError() << std::endl;
                break;
            }

            if (bytesReceived == 0) {
                std::cout << "Client disconnected" << std::endl;
                break;
            }

            send(clientSocket, buf, bytesReceived, 0);
        }

        closesocket(clientSocket);
    }

    // Cleanup
    closesocket(listeningSocket);
    WSACleanup();
    return 0;
}
