#include <windows.h>
#include <stdio.h>

#define IOCTL_TEST 0x8df0004
#define DEVICE_NAME_ADMIN L"\\\\.\\MultiDevAdmin"
#define DEVICE_NAME_PUBLIC L"\\\\.\\MultiDevPublic"

char in_buff[0x20] = {0};
char out_buff[0x20] = {0};
HANDLE hDevice;
DWORD bytesReturned;
BOOL result;
void send_IOCTL(WCHAR *dev_path)
{
	printf("Trying to open the admin device: %S\n", dev_path);
    hDevice = CreateFileW(dev_path, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device %S: %d\n", dev_path, GetLastError());
    }
	else
	{
		printf("Device opened successfully\n");
		printf("Sending IOCTL 0x%X\n", IOCTL_TEST);
		result = DeviceIoControl(hDevice,IOCTL_TEST,in_buff,0x20,out_buff,0x20,&bytesReturned,NULL);
		if (!result) {
			printf("DeviceIoControl failed: %d\n", GetLastError());
		} else {
			printf("IOCTL succeeded, bytes returned: %d\n", bytesReturned);
		}		
		CloseHandle(hDevice);
	}	
}
int main(int argc, char *argv[])
{
    WCHAR devicePath[260];
    swprintf(devicePath, 260, DEVICE_NAME_ADMIN);
	send_IOCTL(devicePath);
    swprintf(devicePath, 260, DEVICE_NAME_PUBLIC);
	send_IOCTL(devicePath);
    return 0;
}
