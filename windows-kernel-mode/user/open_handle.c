// Compile with:
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /Tc open_handle.c /link /OUT:open_handle.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
// A simple test program demonstrating how dwDesiredAccess impacts the ability to open a handle to a device object (using PhysicalDriver0 with (A;;FA;;;BA)(A;;FA;;;SY)(A;;FX;;;WD)(A;;FX;;;RC)(A;;0x12019f;;;UD) as an example).
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    HANDLE hDisk;
    hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return 1;
    }
    CloseHandle(hDisk);
    return 0;
}
