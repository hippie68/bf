# bf
Small C library to run brute-force attacks with generated ASCII passwords.  
It employs multi-threading and can resume previous runs.

The documentation is included in the file `bf.h`.

An example program that runs on Linux/UNIX can be compiled with GCC: `gcc *.c -O3 -lpthread`.  
A Windows version can be compiled with MinGW: `x86_64-w64-mingw32-gcc-win32 *.c -O3 -lpthread`.
