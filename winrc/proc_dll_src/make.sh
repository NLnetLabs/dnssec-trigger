#i686-pc-mingw32-gcc processes.cpp -o bla.dll -mdll -nodefaultlibs -luser32 -lgcc -lmoldname -lmingw32 -lmsvcrt -lkernel32
set -v
i686-pc-mingw32-gcc -g -O2 processes.c -o proc.dll -mdll -nostartfiles -e __DllMainCRTStartup@12
ls -l proc.dll
i686-pc-mingw32-strip proc.dll
ls -l proc.dll
