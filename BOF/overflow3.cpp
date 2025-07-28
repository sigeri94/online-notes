#include <iostream>
#include <cstdlib>
#include <cstring>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

void hidden() {
    std::cout << "[+] Hidden function executed! \n";
    system("calc.exe");
    exit(0);
}

void vulnerable(char* input) {
    char buffer[275];
    strcpy(buffer, input); // vulnerable copy
}

int main() {
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrSize = sizeof(clientAddr);
    char recvBuffer[1024];

    std::cout << "[*] Starting vulnerable server...\n";

    WSAStartup(MAKEWORD(2,2), &wsaData);
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, 1);

    std::cout << "[*] Waiting for connection on port 4444...\n";
    clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
    std::cout << "[*] Client connected.\n";

    memset(recvBuffer, 0, sizeof(recvBuffer));
    recv(clientSocket, recvBuffer, sizeof(recvBuffer) - 1, 0);
    std::cout << "[*] Received: " << recvBuffer << "\n";

    vulnerable(recvBuffer);  // vulnerable input

    std::cout << "[*] Closing connection.\n";
    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
