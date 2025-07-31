#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <cstring>

#pragma comment(lib, "ws2_32.lib") // Link with Winsock library

// Compilation: x86_64-w64-mingw32-g++ -o overflow.exe overflow.cpp -fno-stack-protector -no-pie -lws2_32

void win_function() {
    std::cout << "You have successfully exploited the program!\n";
    system("calc.exe"); // PoC: launches calculator
}

void vulnerable_function(SOCKET clientSocket) {
    char buffer[275]; // Vulnerable buffer

    std::cout << "[*] Waiting for input over socket...\n";

    // Receive data from client into buffer (unsafe!)
    int recvSize = recv(clientSocket, buffer, sizeof(buffer) + 100, 0); // intentionally unsafe
    if (recvSize == SOCKET_ERROR) {
        std::cerr << "[-] recv failed with error: " << WSAGetLastError() << std::endl;
        return;
    }

    std::cout << "[*] Received " << recvSize << " bytes\n";
}

int main() {
    // Allocate memory (optional, for shellcode testing)
    LPVOID allocatedMemory = VirtualAlloc(
        NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (allocatedMemory != NULL) {
        printf("[*] Memory allocated at %p\n", allocatedMemory);
    } else {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
    }

    std::cout << "[*] Initializing Winsock...\n";

    // Winsock init
    WSADATA wsaData;
    int wsInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsInit != 0) {
        std::cerr << "[-] WSAStartup failed: " << wsInit << std::endl;
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[-] socket failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[-] bind failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, 1) == SOCKET_ERROR) {
        std::cerr << "[-] listen failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[*] Listening on port 4444...\n";

    SOCKET clientSocket = accept(serverSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "[-] accept failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[+] Client connected!\n";

    vulnerable_function(clientSocket);

    std::cout << "[*] Closing sockets...\n";
    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();

    std::cout << "[*] Goodbye!\n";
    return 0;
}
