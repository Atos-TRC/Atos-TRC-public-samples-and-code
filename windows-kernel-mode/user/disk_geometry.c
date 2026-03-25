// Compile with:
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /Tc disk_geometry.c /link /OUT:disk_geometry.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
// A very simple example demonstrating the ability to successfully send IOCTL of FILE_ANY_ACCESS Access with explicit dwDesiredAccess = 0.
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    HANDLE hDisk;
    DISK_GEOMETRY geo;
    DWORD bytes;

    hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return 1;
    }
    if (!DeviceIoControl(hDisk,
                         IOCTL_DISK_GET_DRIVE_GEOMETRY,
                         NULL, 0,
                         &geo, sizeof(geo),
                         &bytes, NULL)) {
        printf("DeviceIoControl failed: %lu\n", GetLastError());
        CloseHandle(hDisk);
        return 1;
    }
    printf("Cylinders:          %lld\n", geo.Cylinders.QuadPart);
    printf("MediaType:          %d\n",   geo.MediaType);
    printf("TracksPerCylinder:  %lu\n",  geo.TracksPerCylinder);
    printf("SectorsPerTrack:    %lu\n",  geo.SectorsPerTrack);
    printf("BytesPerSector:     %lu\n",  geo.BytesPerSector);
    CloseHandle(hDisk);
    return 0;
}
