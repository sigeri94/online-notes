#include <iostream>
#include <cstdlib>

void hidden() {
    std::cout << "[+] Hidden function executed! \n";
    system("calc.exe");
    exit(0);
}

void vulnerable() {
    char buffer[275];
    std::cout << "Enter your input: ";
    scanf("%s", buffer); 
}

int main() {
    std::cout << "Welcome to buffer overflow demo.\n";
    vulnerable();
    std::cout << "Goodbye!\n";
    return 0;
}
