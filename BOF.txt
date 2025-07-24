set PATH=%PATH%;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build

vcvars64.bat
cl overflow.cpp /nologo /Feoverflow.exe /GS- /Od /link /DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO /FIXED

i686-w64-mingw32-g++ overflow2.cpp -o overflow2-x86-mingw.exe -static -fno-stack-protector -no-pie
x86_64-w64-mingw32-g++ overflow2.cpp -o overflow2-x64-mingw.exe -static -fno-stack-protector -no-pie

---
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
