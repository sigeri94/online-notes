set PATH=%PATH%;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build

vcvars64.bat
cl overflow.cpp /nologo /Feoverflow.exe /GS- /Od /link /DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO /FIXED

i686-w64-mingw32-g++ overflow2.cpp -o overflow2-x86-mingw.exe -static -fno-stack-protector -no-pie
x86_64-w64-mingw32-g++ overflow2.cpp -o overflow2-x64-mingw.exe -static -fno-stack-protector -no-pie
