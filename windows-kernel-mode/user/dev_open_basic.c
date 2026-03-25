#include <windows.h>
#include <stdio.h>

#define IOCTL_TEST 0x8df0004
#define DEVICE_NAME L"\\\\.\\SampleDrv"

int main(int argc, char *argv[])
{
    WCHAR devicePath[260];
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    char in_buff[0x30] = {0};
	char out_buff[0x28] = {0};
    swprintf(devicePath, 260, DEVICE_NAME);
    printf("Device path: %S\n", devicePath);
    
    hDevice = CreateFileW(devicePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device %S: %d\n", devicePath, GetLastError());
        return 1;
    }
    printf("Device opened successfully\n");
    printf("Sending IOCTL 0x%X\n", IOCTL_TEST);
    result = DeviceIoControl(hDevice,IOCTL_TEST,in_buff,0x30,out_buff,0x28,&bytesReturned,NULL);
    
    if (!result) {
        printf("DeviceIoControl failed: %d\n", GetLastError());
    } else {
        printf("IOCTL succeeded, bytes returned: %d\n", bytesReturned);
    }
    CloseHandle(hDevice);
    return result ? 0 : 1;
}
