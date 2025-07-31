--] compile
x86_64-w64-mingw32-g++ -o overflow.exe overflow.cpp -fno-stack-protector -no-pie -lws2_32

--] ouput of overflow3.exe
batman@DESKTOP-PLG5DB6 C:\Users\batman\Downloads
$ overflow3.exe
[*] Memory allocated at 0000000000dc0000
[*] Initializing Winsock...
[*] Listening on port 4444...
[+] Client connected!
[*] Waiting for input over socket...
[*] Received 375 bytes

--] on x64dbg
search for all module string reference
search "Waiting for input"
search for "ret" and applied break

also search for "You have successfully exploited"
take note of the address
