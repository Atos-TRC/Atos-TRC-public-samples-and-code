// This command line tool allows bidirectional mapping of device objects to drivers and vice versa.
// It works by temoporarily deploying the kldbgdrv.sys driver (Microsoft signed debug driver) to obtain information about relationship between driver objects and device objects.
// Bidirectional mapping:
//   \Device\X -> Returns the driver name that owns the device (e.g. \Device\Null -> \Driver\Null)
//   \Driver\X -> Returns all device names belonging to that driver (e.g. \Driver\kbdclass -> KeyboardClass0 KeyboardClass1 ...)

// Usage samples:
// dev_map_kldbg.exe \Driver\SampleDrv -driver .\kldbgdrv.sys
// [RESULT] Device Names: SampleDrvDev

// dev_map_kldbg.exe \Device\SampleDrvDev -driver .\kldbgdrv.sys
// [RESULT] Driver Name: \Driver\SampleDrv

// Compile with: cl /W4 dev_map_kldbg.c /link ntdll.lib
// Inspired by WinObjEx64 https://github.com/hfiref0x/WinObjEx64

// The tool now also supports interactive mode. When no argument is provided via command line, the tool runs in a loop, reading arguments from standard input. This way mulitiple requests will be handled in a single driver load session (to optimize mapping of large numbers of items, e.g. the entire system, integrating with dev-map.ps1)
// To exit the tool while in interactive mode, "q" or "quit" needs to be provided on stdin.

/*
Important: Since the driver uses exclusive access (ShareAccess=0), if WinObjEx64 (or other tool) already has the handle open, running this tool will result in STATUS_SHARING_VIOLATION.
Important 2: Loading this driver requires Device Guard's memory integrity off (Settings -> Privacy & security -> Windows Security -> Device security -> Core isolation -> Memory integrity = Off. Otherwise you'll get "NtLoadDriver failed: 0xC0E90002" from this program and trying to load the driver with "sc.exe start kldbgdrv" ending up with "[SC] StartService FAILED 4551".
*/

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

//
// Disable warning C4201: nonstandard extension used: nameless struct/union
// This is standard practice for Windows kernel structure definitions
//
#pragma warning(disable: 4201)

//
// InitializeObjectAttributes macro - not always defined in winternl.h
//
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

//
// NTSTATUS codes - defined here to avoid including ntstatus.h
//
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION    ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED     ((NTSTATUS)0xC000010EL)
#endif

//
// OBJ_CASE_INSENSITIVE - may not be defined
//
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

//
// IOCTL for kldbgdrv
//
#define IOCTL_KD_PASS_THROUGH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define DIRECTORY_QUERY                 (0x0001)
// Takenm from C:\Program Files (x86)\Windows Kits\10\\include\10.0.26100.0\\shared\ntstatus.h
// MessageId: STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

//
// System debug commands
//
typedef enum _SYSDBG_COMMAND {
    SysDbgReadVirtual = 8
} SYSDBG_COMMAND;

//
// Structure for SysDbgReadVirtual
//
typedef struct _SYSDBG_VIRTUAL {
    PVOID Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

//
// KLDBG request structure
//
typedef struct _KLDBG {
    SYSDBG_COMMAND SysDbgRequest;
    PVOID Buffer;
    DWORD BufferSize;
} KLDBG, *PKLDBG;

//
// Object header info flags
//
typedef enum _OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag = 0x2,
    HeaderHandleInfoFlag = 0x4,
    HeaderQuotaInfoFlag = 0x8,
    HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;

//
// Kernel object structures
//
#define NUMBER_HASH_BUCKETS 37

#pragma pack(push, 8)

typedef struct _OBJECT_HEADER_NAME_INFO {
    struct _OBJECT_DIRECTORY* Directory;
    UNICODE_STRING Name;
    LONG ReferenceCount;
    ULONG Reserved;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;

typedef struct _OBJECT_HEADER_CREATOR_INFO {
    LIST_ENTRY TypeList;
    PVOID CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Reserved1;
    ULONG Reserved2;
} OBJECT_HEADER_CREATOR_INFO, *POBJECT_HEADER_CREATOR_INFO;

typedef struct _OBJECT_HEADER_HANDLE_INFO {
    union {
        PVOID HandleCountDataBase;
        struct {
            ULONG_PTR SingleEntry;
        };
    };
} OBJECT_HEADER_HANDLE_INFO, *POBJECT_HEADER_HANDLE_INFO;

typedef struct _OBJECT_HEADER_QUOTA_INFO {
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    ULONG Reserved1;
    PVOID SecurityDescriptorQuotaBlock;
    ULONG64 Reserved2;
} OBJECT_HEADER_QUOTA_INFO, *POBJECT_HEADER_QUOTA_INFO;

typedef struct _OBJECT_HEADER_PROCESS_INFO {
    PVOID ExclusiveProcess;
    ULONG64 Reserved;
} OBJECT_HEADER_PROCESS_INFO, *POBJECT_HEADER_PROCESS_INFO;

typedef struct _QUAD {
    union {
        INT64 UseThisFieldToCopy;
        float DoNotUseThisField;
    };
} QUAD, *PQUAD;

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    PVOID Lock;
    UCHAR TypeIndex;
    union {
        UCHAR TraceFlags;
        struct {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };
    UCHAR InfoMask;
    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    ULONG Reserved;
    union {
        PVOID ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
    POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
    PVOID Lock;
    PVOID DeviceMap;
    ULONG SessionId;
    PVOID NamespaceEntry;
    ULONG Flags;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

#pragma pack(pop)

//
// DEVICE_OBJECT simplified - we need DriverObject and NextDevice fields
//
typedef struct _DEVICE_OBJECT_MINIMAL {
    SHORT Type;                 // +0x000
    USHORT Size;                // +0x002
    LONG ReferenceCount;        // +0x004
    PVOID DriverObject;         // +0x008 - PDRIVER_OBJECT
    PVOID NextDevice;           // +0x010 - Next device in driver's device list
    // ... more fields follow but we don't need them
} DEVICE_OBJECT_MINIMAL, *PDEVICE_OBJECT_MINIMAL;

//
// DRIVER_OBJECT structure - enough fields to reach DriverName
// Based on Windows 10+ layout
//
typedef struct _DRIVER_OBJECT_MINIMAL {
    SHORT Type;                         // +0x000
    SHORT Size;                         // +0x002
    PVOID DeviceObject;                 // +0x008
    ULONG Flags;                        // +0x010
    PVOID DriverStart;                  // +0x018
    ULONG DriverSize;                   // +0x020
    PVOID DriverSection;                // +0x028
    PVOID DriverExtension;              // +0x030
    UNICODE_STRING DriverName;          // +0x038 - This is what we want
    // ... more fields follow (HardwareDatabase, FastIoDispatch, etc.)
} DRIVER_OBJECT_MINIMAL, *PDRIVER_OBJECT_MINIMAL;

//
// Macro to convert object address to object header address
//
#define OBJECT_TO_OBJECT_HEADER(o) \
    ((POBJECT_HEADER)((ULONG_PTR)(o) - (ULONG_PTR)FIELD_OFFSET(OBJECT_HEADER, Body)))

//
// System range start (for validation)
//
#define MM_SYSTEM_RANGE_START 0xFFFF800000000000ULL

//
// Undocumented NT functions
//
typedef NTSTATUS(NTAPI* PFN_NtOpenDirectoryObject)(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PFN_NtCreateFile)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_opt_ PVOID EaBuffer,
    _In_ ULONG EaLength
    );

typedef NTSTATUS(NTAPI* PFN_NtLoadDriver)(
    _In_ PUNICODE_STRING DriverServiceName
    );

typedef NTSTATUS(NTAPI* PFN_NtUnloadDriver)(
    _In_ PUNICODE_STRING DriverServiceName
    );

typedef NTSTATUS(NTAPI* PFN_RtlAdjustPrivilege)(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
    );

typedef BOOLEAN(NTAPI* PFN_RtlDosPathNameToNtPathName_U)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR* FilePart,
    _Reserved_ PVOID Reserved
    );

typedef VOID(NTAPI* PFN_RtlFreeUnicodeString)(
    _Inout_ PUNICODE_STRING UnicodeString
    );

#define SE_LOAD_DRIVER_PRIVILEGE 10
#define SE_DEBUG_PRIVILEGE 20

#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

//
// Global driver handle and function pointers
//
static HANDLE g_hDevice = NULL;
static BOOL g_bDriverLoadedByUs = FALSE;
static PFN_NtOpenDirectoryObject NtOpenDirectoryObject = NULL;
static PFN_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
static PFN_NtCreateFile pNtCreateFile = NULL;
static PFN_NtLoadDriver pNtLoadDriver = NULL;
static PFN_NtUnloadDriver pNtUnloadDriver = NULL;
static PFN_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;
static PFN_RtlDosPathNameToNtPathName_U pRtlDosPathNameToNtPathName_U = NULL;
static PFN_RtlFreeUnicodeString pRtlFreeUnicodeString = NULL;

// Driver service registry key path
#define DRIVER_REGISTRY_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\kldbgdrv"

/*
* KdReadSystemMemory
*
* Purpose:
*   Read kernel virtual memory through kldbgdrv driver.
*/
BOOL KdReadSystemMemory(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize
)
{
    NTSTATUS ntStatus;
    IO_STATUS_BLOCK iosb = { 0 };
    SYSDBG_VIRTUAL dbgRequest;
    KLDBG kldbg;

    if (g_hDevice == NULL || Address < MM_SYSTEM_RANGE_START)
        return FALSE;

    // Setup the debug request
    dbgRequest.Address = (PVOID)Address;
    dbgRequest.Buffer = Buffer;
    dbgRequest.Request = BufferSize;

    // Setup KLDBG structure
    kldbg.SysDbgRequest = SysDbgReadVirtual;
    kldbg.Buffer = &dbgRequest;
    kldbg.BufferSize = sizeof(SYSDBG_VIRTUAL);

    ntStatus = NtDeviceIoControlFile(
        g_hDevice,
        NULL,
        NULL,
        NULL,
        &iosb,
        IOCTL_KD_PASS_THROUGH,
        &kldbg,
        sizeof(kldbg),
        &dbgRequest,
        sizeof(dbgRequest));

    if (ntStatus == STATUS_PENDING) {
        NtWaitForSingleObject(g_hDevice, FALSE, NULL);
        ntStatus = iosb.Status;
    }

    if (!NT_SUCCESS(ntStatus)) {
        wprintf(L"[DEBUG] KdReadSystemMemory failed: ntStatus=0x%08X, iosb.Status=0x%08X, Address=0x%llX, Size=%u\n",
            ntStatus, (NTSTATUS)iosb.Status, Address, BufferSize);
    }

    return NT_SUCCESS(ntStatus) && NT_SUCCESS(iosb.Status);
}

/*
* CreateDriverRegistryEntry
*
* Purpose:
*   Create registry entry for the driver service.
*   Converts DOS path to NT path format for ImagePath.
*/
BOOL CreateDriverRegistryEntry(
    _In_ LPCWSTR DriverPath
)
{
    HKEY hKey = NULL;
    DWORD dwType = 1;  // SERVICE_KERNEL_DRIVER
    DWORD dwStart = 3; // SERVICE_DEMAND_START
    DWORD dwError = 1; // SERVICE_ERROR_NORMAL
    LONG result;
    UNICODE_STRING ntPath;
    BOOL bResult = FALSE;

    // Convert DOS path to NT path (e.g., C:\path\driver.sys -> \??\C:\path\driver.sys)
    if (!pRtlDosPathNameToNtPathName_U(DriverPath, &ntPath, NULL, NULL)) {
        wprintf(L"[DEBUG] Failed to convert path to NT format\n");
        return FALSE;
    }

    wprintf(L"[DEBUG] NT ImagePath: %wZ\n", &ntPath);

    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Services\\kldbgdrv",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        NULL);

    if (result != ERROR_SUCCESS) {
        wprintf(L"[DEBUG] Failed to create registry key: %d\n", result);
        pRtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwType, sizeof(dwType));
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwStart, sizeof(dwStart));
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwError, sizeof(dwError));
    
    // Use NT path format with null terminator
    result = RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, 
        (BYTE*)ntPath.Buffer, ntPath.Length + sizeof(UNICODE_NULL));
    
    if (result == ERROR_SUCCESS) {
        bResult = TRUE;
    } else {
        wprintf(L"[DEBUG] Failed to set ImagePath: %d\n", result);
    }

    RegCloseKey(hKey);
    pRtlFreeUnicodeString(&ntPath);
    return bResult;
}

/*
* DeleteDriverRegistryEntry
*
* Purpose:
*   Delete registry entry for the driver service.
*/
VOID DeleteDriverRegistryEntry(VOID)
{
	wprintf(L"[DEBUG] DeleteDriverRegistryEntry() is currently disabled.\n");
    //RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\kldbgdrv");
}

/*
* LoadKldbgDriver
*
* Purpose:
*   Load kldbgdrv.sys driver.
*/
NTSTATUS LoadKldbgDriver(
    _In_ LPCWSTR DriverPath
)
{
    NTSTATUS ntStatus;
    UNICODE_STRING driverServiceName;
    BOOLEAN wasEnabled;

    wprintf(L"[DEBUG] Attempting to load driver from: %s\n", DriverPath);

    // Check if driver file exists
    if (GetFileAttributesW(DriverPath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[DEBUG] Driver file not found: %s\n", DriverPath);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Create registry entry
    if (!CreateDriverRegistryEntry(DriverPath)) {
		wprintf(L"[DEBUG]] WARNING: Failed to create registry key.\n");
        //return STATUS_UNSUCCESSFUL; // ignore error
    }
//	wprintf(L"[DEBUG] Registry path apparently created.\n");

    // Enable SeLoadDriverPrivilege
    ntStatus = pRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &wasEnabled);
    if (!NT_SUCCESS(ntStatus)) {
        wprintf(L"[DEBUG] Failed to enable SeLoadDriverPrivilege: 0x%08X\n", ntStatus);
        DeleteDriverRegistryEntry();
        return ntStatus;
    }

    // Load driver
    RtlInitUnicodeString(&driverServiceName, DRIVER_REGISTRY_KEY);
    
    wprintf(L"[DEBUG] Registry path: %wZ\n", &driverServiceName);
    wprintf(L"[DEBUG] Length: %u, MaxLength: %u\n", driverServiceName.Length, driverServiceName.MaximumLength);
    
    ntStatus = pNtLoadDriver(&driverServiceName);

    if (ntStatus == STATUS_IMAGE_ALREADY_LOADED ||
        ntStatus == STATUS_OBJECT_NAME_COLLISION) {
        wprintf(L"[DEBUG] Driver already loaded\n");
        ntStatus = STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(ntStatus)) {
        wprintf(L"[DEBUG] NtLoadDriver failed: 0x%08X\n", ntStatus);
        DeleteDriverRegistryEntry();
    }
    else {
        wprintf(L"[DEBUG] Driver loaded successfully\n");
        g_bDriverLoadedByUs = TRUE;
    }

    return ntStatus;
}

/*
* UnloadKldbgDriver
*
* Purpose:
*   Unload kldbgdrv.sys driver if we loaded it.
*/
VOID UnloadKldbgDriver(VOID)
{
    UNICODE_STRING driverServiceName;
    BOOLEAN wasEnabled;

    if (!g_bDriverLoadedByUs)
        return;

    wprintf(L"[DEBUG] Unloading driver...\n");

    pRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &wasEnabled);
    RtlInitUnicodeString(&driverServiceName, DRIVER_REGISTRY_KEY);
    pNtUnloadDriver(&driverServiceName);
    DeleteDriverRegistryEntry();
    g_bDriverLoadedByUs = FALSE;
}

/*
* InitializeDriver
*
* Purpose:
*   Open handle to kldbgdrv device, loading driver if necessary.
*/
BOOL InitializeDriver(
    _In_opt_ LPCWSTR DriverPath
)
{
    HANDLE hDevice = NULL;
    HMODULE hNtdll;
    NTSTATUS ntStatus;
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    WCHAR szDriverPath[MAX_PATH];

    // Get NT functions
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL)
        return FALSE;

    NtOpenDirectoryObject = (PFN_NtOpenDirectoryObject)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pNtCreateFile = (PFN_NtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    pNtLoadDriver = (PFN_NtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
    pNtUnloadDriver = (PFN_NtUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
    pRtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    pRtlDosPathNameToNtPathName_U = (PFN_RtlDosPathNameToNtPathName_U)GetProcAddress(hNtdll, "RtlDosPathNameToNtPathName_U");
    pRtlFreeUnicodeString = (PFN_RtlFreeUnicodeString)GetProcAddress(hNtdll, "RtlFreeUnicodeString");

    if (NtOpenDirectoryObject == NULL || pNtQuerySystemInformation == NULL || 
        pNtCreateFile == NULL || pNtLoadDriver == NULL || pNtUnloadDriver == NULL ||
        pRtlAdjustPrivilege == NULL || pRtlDosPathNameToNtPathName_U == NULL ||
        pRtlFreeUnicodeString == NULL)
        return FALSE;

    // First try to open existing device
    RtlInitUnicodeString(&deviceName, L"\\Device\\kldbgdrv");
    InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = pNtCreateFile(
        &hDevice,
        SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &iosb,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (NT_SUCCESS(ntStatus)) {
        wprintf(L"[DEBUG] Device already exists, opened successfully\n");
        g_hDevice = hDevice;
        
        // Enable SeDebugPrivilege - required for KdSystemDebugControl
        BOOLEAN wasEnabled;
        ntStatus = pRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasEnabled);
        if (!NT_SUCCESS(ntStatus)) {
            wprintf(L"[DEBUG] Warning: Failed to enable SeDebugPrivilege: 0x%08X\n", ntStatus);
        } else {
            wprintf(L"[DEBUG] SeDebugPrivilege enabled\n");
        }
        return TRUE;
    }

    wprintf(L"[DEBUG] Device not found (0x%08X), attempting to load driver...\n", ntStatus);

    // Device doesn't exist, need to load driver
    if (DriverPath == NULL) {
        // Try default paths
        GetSystemDirectoryW(szDriverPath, MAX_PATH);
        wcscat_s(szDriverPath, MAX_PATH, L"\\drivers\\kldbgdrv.sys");
        DriverPath = szDriverPath;
    }

    ntStatus = LoadKldbgDriver(DriverPath);
    if (!NT_SUCCESS(ntStatus)) {
        wprintf(L"[DEBUG] Failed to load driver\n");
        wprintf(L"[DEBUG]    Make sure:\n");
        wprintf(L"[DEBUG]    1. Windows Debug Mode is enabled (bcdedit /debug on)\n");
        wprintf(L"[DEBUG]    2. You have rebooted after enabling debug mode\n");
        wprintf(L"[DEBUG]    3. kldbgdrv.sys exists at: %s\n", DriverPath);
        wprintf(L"[DEBUG]    4. You are running as Administrator\n");
        return FALSE;
    }

    // Try to open device again after loading
    ntStatus = pNtCreateFile(
        &hDevice,
        SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &iosb,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (NT_SUCCESS(ntStatus)) {
        g_hDevice = hDevice;
        
        // Enable SeDebugPrivilege - required for KdSystemDebugControl
        BOOLEAN wasEnabled;
        ntStatus = pRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasEnabled);
        if (!NT_SUCCESS(ntStatus)) {
            wprintf(L"[DEBUG] Warning: Failed to enable SeDebugPrivilege: 0x%08X\n", ntStatus);
        } else {
            wprintf(L"[DEBUG] SeDebugPrivilege enabled\n");
        }
        return TRUE;
    }

    wprintf(L"[DEBUG] Failed to open device after loading: NTSTATUS 0x%08X\n", ntStatus);
    wprintf(L"[DEBUG]    This usually means debug mode is not enabled.\n");
    wprintf(L"[DEBUG]    The driver loaded but couldn't create device because\n");
    wprintf(L"[DEBUG]    KdSystemDebugControl is not available.\n");
    UnloadKldbgDriver();
    return FALSE;
}

/*
* CleanupDriver
*
* Purpose:
*   Close driver handle and unload driver if we loaded it.
*/
VOID CleanupDriver(VOID)
{
    if (g_hDevice != NULL) {
        NtClose(g_hDevice);
        g_hDevice = NULL;
    }

    // Unload driver if we loaded it
    UnloadKldbgDriver();
}

/*
* ObGetObjectHeaderOffset
*
* Purpose:
*   Calculate offset to object header info structure.
*/
BYTE ObGetObjectHeaderOffset(
    _In_ BYTE InfoMask,
    _In_ OBJ_HEADER_INFO_FLAG Flag
)
{
    BYTE OffsetMask, HeaderOffset = 0;

    if ((InfoMask & Flag) == 0)
        return 0;

    OffsetMask = InfoMask & (Flag | (Flag - 1));

    if ((OffsetMask & HeaderCreatorInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_CREATOR_INFO);

    if ((OffsetMask & HeaderNameInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);

    if ((OffsetMask & HeaderHandleInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_HANDLE_INFO);

    if ((OffsetMask & HeaderQuotaInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_QUOTA_INFO);

    if ((OffsetMask & HeaderProcessInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_PROCESS_INFO);

    return HeaderOffset;
}

/*
* QueryObjectAddressFromHandle
*
* Purpose:
*   Get kernel object address from a user-mode handle using handle table dump.
*/
BOOL QueryObjectAddressFromHandle(
    _In_ HANDLE ObjectHandle,
    _Out_ PULONG_PTR ObjectAddress
)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus;
    ULONG bufferSize = 0x100000;
    PVOID buffer = NULL;
    ULONG returnLength;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
    ULONG_PTR currentPid = (ULONG_PTR)GetCurrentProcessId();

    *ObjectAddress = 0;

    // Allocate buffer for handle information
    do {
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buffer == NULL)
            return FALSE;

        ntStatus = pNtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer,
            bufferSize,
            &returnLength);

        if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            bufferSize *= 2;
            buffer = NULL;
        }
    } while (ntStatus == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 0x10000000);

    if (!NT_SUCCESS(ntStatus)) {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    // Search for our handle
    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        if (handleInfo->Handles[i].UniqueProcessId == currentPid &&
            handleInfo->Handles[i].HandleValue == (ULONG_PTR)ObjectHandle) {
            *ObjectAddress = (ULONG_PTR)handleInfo->Handles[i].Object;
            bResult = TRUE;
            break;
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return bResult;
}

/*
* OpenDirectoryByName
*
* Purpose:
*   Open object directory by name.
*/
NTSTATUS OpenDirectoryByName(
    _In_ PUNICODE_STRING DirectoryName,
    _Out_ PHANDLE DirectoryHandle
)
{
    OBJECT_ATTRIBUTES objAttr;

    InitializeObjectAttributes(&objAttr, DirectoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenDirectoryObject(DirectoryHandle, DIRECTORY_QUERY, &objAttr);
}

/*
* GetObjectAddressForDirectory
*
* Purpose:
*   Get kernel address of a directory object by opening it and querying handle table.
*/
BOOL GetObjectAddressForDirectory(
    _In_ PCWSTR DirectoryPath,
    _Out_ PULONG_PTR DirectoryAddress
)
{
    HANDLE hDirectory = NULL;
    UNICODE_STRING dirName;
    NTSTATUS ntStatus;
    BOOL bResult = FALSE;

    *DirectoryAddress = 0;

    RtlInitUnicodeString(&dirName, DirectoryPath);
    ntStatus = OpenDirectoryByName(&dirName, &hDirectory);

    if (NT_SUCCESS(ntStatus)) {
        bResult = QueryObjectAddressFromHandle(hDirectory, DirectoryAddress);
        NtClose(hDirectory);
    }

    return bResult;
}

/*
* FindObjectInDirectory
*
* Purpose:
*   Search for an object by name inside a kernel directory.
*   Returns the kernel address of the object if found.
*/
BOOL FindObjectInDirectory(
    _In_ PCWSTR ObjectName,
    _In_ ULONG_PTR DirectoryAddress,
    _Out_ PULONG_PTR ObjectAddress
)
{
    OBJECT_DIRECTORY directory;
    OBJECT_DIRECTORY_ENTRY entry;
    OBJECT_HEADER header;
    OBJECT_HEADER_NAME_INFO nameInfo;
    ULONG_PTR headerAddr, nameInfoAddr, lookupItem;
    WCHAR nameBuffer[256];
    BYTE headerOffset;

    *ObjectAddress = 0;

    // Read the directory object
    if (!KdReadSystemMemory(DirectoryAddress, &directory, sizeof(directory))) {
        wprintf(L"[DEBUG] Failed to read directory at 0x%llX\n", DirectoryAddress);
        return FALSE;
    }

    // Iterate through all hash buckets
    for (ULONG i = 0; i < NUMBER_HASH_BUCKETS; i++) {
        lookupItem = (ULONG_PTR)directory.HashBuckets[i];

        while (lookupItem != 0) {
            // Read directory entry
            if (!KdReadSystemMemory(lookupItem, &entry, sizeof(entry)))
                break;

            if (entry.Object == NULL)
                goto NextEntry;

            // Get object header
            headerAddr = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(entry.Object);
            if (!KdReadSystemMemory(headerAddr, &header, sizeof(header)))
                goto NextEntry;

            // Check if object has name info
            headerOffset = ObGetObjectHeaderOffset(header.InfoMask, HeaderNameInfoFlag);
            if (headerOffset == 0)
                goto NextEntry;

            // Read name info
            nameInfoAddr = headerAddr - headerOffset;
            if (!KdReadSystemMemory(nameInfoAddr, &nameInfo, sizeof(nameInfo)))
                goto NextEntry;

            // Validate and read name string
            if (nameInfo.Name.Length == 0 || nameInfo.Name.Length > sizeof(nameBuffer) - sizeof(WCHAR))
                goto NextEntry;

            RtlZeroMemory(nameBuffer, sizeof(nameBuffer));
            if (!KdReadSystemMemory((ULONG_PTR)nameInfo.Name.Buffer, nameBuffer, nameInfo.Name.Length))
                goto NextEntry;

            // Compare names (case-insensitive)
            if (_wcsicmp(nameBuffer, ObjectName) == 0) {
                *ObjectAddress = (ULONG_PTR)entry.Object;
                return TRUE;
            }

        NextEntry:
            lookupItem = (ULONG_PTR)entry.ChainLink;
        }
    }

    return FALSE;
}

/*
* GetDriverNameFromAddress
*
* Purpose:
*   Read the DriverName from a DRIVER_OBJECT at the given kernel address.
*
* Parameters:
*   DriverObjectAddress - Kernel address of the DRIVER_OBJECT
*   DriverName          - Buffer to receive the driver name
*   DriverNameSize      - Size of the buffer in WCHARs
*
* Returns:
*   TRUE on success, FALSE on failure.
*/
BOOL GetDriverNameFromAddress(
    _In_ ULONG_PTR DriverObjectAddress,
    _Out_writes_(DriverNameSize) PWCHAR DriverName,
    _In_ SIZE_T DriverNameSize
)
{
    DRIVER_OBJECT_MINIMAL driverObject;
    USHORT nameLength;

    if (DriverObjectAddress < MM_SYSTEM_RANGE_START) {
        wprintf(L"[DEBUG] Invalid driver object address\n");
        return FALSE;
    }

    // Read the DRIVER_OBJECT structure
    RtlZeroMemory(&driverObject, sizeof(driverObject));
    if (!KdReadSystemMemory(DriverObjectAddress, &driverObject, sizeof(driverObject))) {
        wprintf(L"[DEBUG] Failed to read DRIVER_OBJECT at 0x%llX\n", DriverObjectAddress);
        return FALSE;
    }

    // Validate DriverName UNICODE_STRING
    if (driverObject.DriverName.Length == 0 || driverObject.DriverName.Buffer == NULL) {
        wprintf(L"[DEBUG] DRIVER_OBJECT has no name\n");
        return FALSE;
    }

    nameLength = driverObject.DriverName.Length;
    if (nameLength >= (DriverNameSize * sizeof(WCHAR))) {
        wprintf(L"[DEBUG] Driver name too long (%u bytes)\n", nameLength);
        return FALSE;
    }

    // Read the driver name string from kernel memory
    RtlZeroMemory(DriverName, DriverNameSize * sizeof(WCHAR));
    if (!KdReadSystemMemory((ULONG_PTR)driverObject.DriverName.Buffer, DriverName, nameLength)) {
        wprintf(L"[DEBUG] Failed to read driver name string\n");
        return FALSE;
    }

    return TRUE;
}

/*
* GetObjectNameFromAddress
*
* Purpose:
*   Read the object name from an object's header name info.
*
* Parameters:
*   ObjectAddress   - Kernel address of the object
*   ObjectName      - Buffer to receive the object name
*   ObjectNameSize  - Size of the buffer in WCHARs
*
* Returns:
*   TRUE on success, FALSE on failure.
*/
BOOL GetObjectNameFromAddress(
    _In_ ULONG_PTR ObjectAddress,
    _Out_writes_(ObjectNameSize) PWCHAR ObjectName,
    _In_ SIZE_T ObjectNameSize
)
{
    OBJECT_HEADER header;
    OBJECT_HEADER_NAME_INFO nameInfo;
    ULONG_PTR headerAddr, nameInfoAddr;
    BYTE headerOffset;

    if (ObjectAddress < MM_SYSTEM_RANGE_START) {
        return FALSE;
    }

    // Get object header
    headerAddr = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER((PVOID)ObjectAddress);
    if (!KdReadSystemMemory(headerAddr, &header, sizeof(header))) {
        return FALSE;
    }

    // Check if object has name info
    headerOffset = ObGetObjectHeaderOffset(header.InfoMask, HeaderNameInfoFlag);
    if (headerOffset == 0) {
        return FALSE;
    }

    // Read name info
    nameInfoAddr = headerAddr - headerOffset;
    if (!KdReadSystemMemory(nameInfoAddr, &nameInfo, sizeof(nameInfo))) {
        return FALSE;
    }

    // Validate name
    if (nameInfo.Name.Length == 0 || nameInfo.Name.Buffer == NULL) {
        return FALSE;
    }

    if (nameInfo.Name.Length >= (ObjectNameSize * sizeof(WCHAR))) {
        return FALSE;
    }

    // Read the name string
    RtlZeroMemory(ObjectName, ObjectNameSize * sizeof(WCHAR));
    if (!KdReadSystemMemory((ULONG_PTR)nameInfo.Name.Buffer, ObjectName, nameInfo.Name.Length)) {
        return FALSE;
    }

    return TRUE;
}

/*
* GetDevicesFromDriverPath
*
* Purpose:
*   Given a driver path like "\\Driver\\Null", returns all device objects
*   belonging to that driver.
*
* Parameters:
*   DriverPath      - Full OMNS path to driver (e.g., L"\\Driver\\Null")
*   DeviceNames     - Buffer to receive space-separated device names
*   DeviceNamesSize - Size of the buffer in WCHARs
*
* Returns:
*   TRUE on success (at least one device found), FALSE on failure.
*/
BOOL GetDevicesFromDriverPath(
    _In_ PCWSTR DriverPath,
    _Out_writes_(DeviceNamesSize) PWCHAR DeviceNames,
    _In_ SIZE_T DeviceNamesSize
)
{
    ULONG_PTR directoryAddress = 0;
    ULONG_PTR driverObjectAddress = 0;
    DRIVER_OBJECT_MINIMAL driverObject;
    DEVICE_OBJECT_MINIMAL deviceObject;
    ULONG_PTR currentDeviceAddr;
    WCHAR directoryPath[MAX_PATH];
    WCHAR deviceName[256];
    PCWSTR driverName;
    SIZE_T currentPos = 0;
    int deviceCount = 0;

    DeviceNames[0] = L'\0';

    // Parse the path to separate directory and object name
    PCWSTR lastBackslash = wcsrchr(DriverPath, L'\\');
    if (lastBackslash == NULL || lastBackslash == DriverPath) {
        wprintf(L"[DEBUG] Invalid driver path format\n");
        return FALSE;
    }

    // Extract directory path
    SIZE_T dirLen = lastBackslash - DriverPath;
    if (dirLen >= MAX_PATH) {
        wprintf(L"[DEBUG] Path too long\n");
        return FALSE;
    }
    wcsncpy_s(directoryPath, MAX_PATH, DriverPath, dirLen);
    directoryPath[dirLen] = L'\0';

    // Driver name is after the last backslash
    driverName = lastBackslash + 1;

    wprintf(L"[DEBUG] Directory: %s\n", directoryPath);
    wprintf(L"[DEBUG] Driver name: %s\n", driverName);

    // Step 1: Get the directory kernel address
    if (!GetObjectAddressForDirectory(directoryPath, &directoryAddress)) {
        wprintf(L"[DEBUG] Failed to get directory address for: %s\n", directoryPath);
        return FALSE;
    }
    wprintf(L"[DEBUG] Directory kernel address: 0x%llX\n", directoryAddress);

    // Step 2: Find the driver object in the directory
    if (!FindObjectInDirectory(driverName, directoryAddress, &driverObjectAddress)) {
        wprintf(L"[DEBUG] Driver '%s' not found in directory\n", driverName);
        return FALSE;
    }
    wprintf(L"[DEBUG] Driver object kernel address: 0x%llX\n", driverObjectAddress);

    // Step 3: Read the DRIVER_OBJECT to get DeviceObject (head of device list)
    RtlZeroMemory(&driverObject, sizeof(driverObject));
    if (!KdReadSystemMemory(driverObjectAddress, &driverObject, sizeof(driverObject))) {
        wprintf(L"[DEBUG] Failed to read DRIVER_OBJECT\n");
        return FALSE;
    }

    currentDeviceAddr = (ULONG_PTR)driverObject.DeviceObject;
    wprintf(L"[DEBUG] First device object: 0x%llX\n", currentDeviceAddr);

    if (currentDeviceAddr == 0 || currentDeviceAddr < MM_SYSTEM_RANGE_START) {
        wprintf(L"[DEBUG] Driver has no device objects\n");
        return FALSE;
    }

    // Step 4: Walk the device list and collect names
    while (currentDeviceAddr != 0 && currentDeviceAddr >= MM_SYSTEM_RANGE_START) {
        // Read the device object
        RtlZeroMemory(&deviceObject, sizeof(deviceObject));
        if (!KdReadSystemMemory(currentDeviceAddr, &deviceObject, sizeof(deviceObject))) {
            wprintf(L"[DEBUG] Failed to read DEVICE_OBJECT at 0x%llX\n", currentDeviceAddr);
            break;
        }

        // Get device name from object header
        RtlZeroMemory(deviceName, sizeof(deviceName));
        if (GetObjectNameFromAddress(currentDeviceAddr, deviceName, ARRAYSIZE(deviceName))) {
            SIZE_T nameLen = wcslen(deviceName);

            // Check if we have space (name + space + null terminator)
            if (currentPos + nameLen + 2 < DeviceNamesSize) {
                if (deviceCount > 0) {
                    DeviceNames[currentPos++] = L' ';
                }
                wcscpy_s(&DeviceNames[currentPos], DeviceNamesSize - currentPos, deviceName);
                currentPos += nameLen;
                deviceCount++;
            }
            wprintf(L"[DEBUG] Found device: %s (at 0x%llX)\n", deviceName, currentDeviceAddr);
        } else {
            wprintf(L"[DEBUG] Device at 0x%llX has no name (unnamed device object)\n", currentDeviceAddr);
        }

        // Move to next device in the list
        currentDeviceAddr = (ULONG_PTR)deviceObject.NextDevice;
    }

    wprintf(L"[DEBUG] Total devices found: %d\n", deviceCount);
    return (deviceCount > 0);
}

/*
* GetDriverObjectFromDevicePath
*
* Purpose:
*   Main function - given a device path like "\\Device\\Null", returns
*   the kernel address of the associated DRIVER_OBJECT.
*
* Parameters:
*   DevicePath      - Full OMNS path to device (e.g., L"\\Device\\Null")
*   DriverObjectAddress - Receives the DRIVER_OBJECT kernel address
*
* Returns:
*   TRUE on success, FALSE on failure.
*/
BOOL GetDriverObjectFromDevicePath(
    _In_ PCWSTR DevicePath,
    _Out_ PULONG_PTR DriverObjectAddress
)
{
    ULONG_PTR directoryAddress = 0;
    ULONG_PTR deviceObjectAddress = 0;
    DEVICE_OBJECT_MINIMAL deviceObject;
    WCHAR directoryPath[MAX_PATH];
    PCWSTR deviceName;

    *DriverObjectAddress = 0;

    // Parse the path to separate directory and object name
    // e.g., "\\Device\\Null" -> directory="\\Device", name="Null"
    PCWSTR lastBackslash = wcsrchr(DevicePath, L'\\');
    if (lastBackslash == NULL || lastBackslash == DevicePath) {
        wprintf(L"[DEBUG] Invalid device path format\n");
        return FALSE;
    }

    // Extract directory path
    SIZE_T dirLen = lastBackslash - DevicePath;
    if (dirLen >= MAX_PATH) {
        wprintf(L"[DEBUG] Path too long\n");
        return FALSE;
    }
    wcsncpy_s(directoryPath, MAX_PATH, DevicePath, dirLen);
    directoryPath[dirLen] = L'\0';

    // Device name is after the last backslash
    deviceName = lastBackslash + 1;

    wprintf(L"[DEBUG] Directory: %s\n", directoryPath);
    wprintf(L"[DEBUG] Device name: %s\n", deviceName);

    // Step 1: Get the directory kernel address
    if (!GetObjectAddressForDirectory(directoryPath, &directoryAddress)) {
        wprintf(L"[DEBUG] Failed to get directory address for: %s\n", directoryPath);
        return FALSE;
    }
    wprintf(L"[DEBUG] Directory kernel address: 0x%llX\n", directoryAddress);

    // Step 2: Find the device object in the directory
    if (!FindObjectInDirectory(deviceName, directoryAddress, &deviceObjectAddress)) {
        wprintf(L"[DEBUG] Device '%s' not found in directory\n", deviceName);
        return FALSE;
    }
    wprintf(L"[DEBUG] Device object kernel address: 0x%llX\n", deviceObjectAddress);

    // Step 3: Read the DEVICE_OBJECT to get DriverObject field
    if (!KdReadSystemMemory(deviceObjectAddress, &deviceObject, sizeof(deviceObject))) {
        wprintf(L"[DEBUG] Failed to read DEVICE_OBJECT\n");
        return FALSE;
    }

    *DriverObjectAddress = (ULONG_PTR)deviceObject.DriverObject;
    wprintf(L"[DEBUG] Driver object kernel address: 0x%llX\n", *DriverObjectAddress);

    return TRUE;
}

/*
* ProcessObjectPath
*
* Purpose:
*   Perform a single lookup for the given object path.
*   Handles both \Device\... and \Driver\... paths.
*/
VOID ProcessObjectPath(
    _In_ PCWSTR ObjectPath
)
{
    ULONG_PTR driverObjectAddress = 0;
    WCHAR driverName[512];
    WCHAR deviceNames[4096];
    BOOL isDriverPath;

    // Detect mode based on path prefix
    if (_wcsnicmp(ObjectPath, L"\\Driver\\", 8) == 0) {
        isDriverPath = TRUE;
    } else if (_wcsnicmp(ObjectPath, L"\\Device\\", 8) == 0) {
        isDriverPath = FALSE;
    } else {
        wprintf(L"[DEBUG] Error: Path must start with \\Device\\ or \\Driver\\\n");
        return;
    }

    if (isDriverPath) {
        // Mode: \Driver\X -> list of devices
        wprintf(L"[DEBUG] Looking up devices for driver: %s\n", ObjectPath);
        if (GetDevicesFromDriverPath(ObjectPath, deviceNames, ARRAYSIZE(deviceNames))) {
            wprintf(L"[RESULT] Device Names: %s\n", deviceNames);
        } else {
            wprintf(L"[DEBUG] FAILED to get devices for driver (or driver has no named devices)\n");
        }
    } else {
        // Mode: \Device\X -> driver name
        wprintf(L"[DEBUG] Looking up driver for device: %s\n", ObjectPath);
        if (GetDriverObjectFromDevicePath(ObjectPath, &driverObjectAddress)) {
            wprintf(L"[DEBUG] SUCCESS: DRIVER_OBJECT at 0x%llX\n", driverObjectAddress);

            wprintf(L"[DEBUG] Reading driver name...\n");
            if (GetDriverNameFromAddress(driverObjectAddress, driverName, ARRAYSIZE(driverName))) {
                wprintf(L"[RESULT] Driver Name: %s\n", driverName);
            } else {
                wprintf(L"[DEBUG] Failed to read driver name\n");
            }
        } else {
            wprintf(L"\n[DEBUG] FAILED to get driver object\n");
        }
    }
}

int wmain(int argc, wchar_t* argv[])
{
    PCWSTR objectPath = NULL;
    PCWSTR kldbgDriverPath = NULL;
    int i;

    // Parse arguments
    for (i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"-driver") == 0 && i + 1 < argc) {
            kldbgDriverPath = argv[++i];
        }
        else if (argv[i][0] != L'-') {
            objectPath = argv[i];
        }
    }

    if (objectPath == NULL) {
        wprintf(L"Usage: %s [path] [-driver <kldbgdrv.sys_path>]\n", argv[0]);
        wprintf(L"\nModes (auto-detected based on path prefix):\n");
        wprintf(L"  \\Device\\...  ->  Returns the driver name for the device\n");
        wprintf(L"  \\Driver\\...  ->  Returns all device names for the driver\n");
        wprintf(L"\nExamples:\n");
        wprintf(L"  %s \\Device\\Null\n", argv[0]);
        wprintf(L"  %s \\Driver\\Null\n", argv[0]);
        wprintf(L"  %s \\Device\\KeyboardClass0 -driver C:\\kldbgdrv.sys\n\n", argv[0]);
        wprintf(L"If no path is given, interactive mode is started (type 'q' or 'quit' to exit).\n\n");
    }

    // Initialize the driver connection (will load driver if needed)
    wprintf(L"[DEBUG] Initializing kldbgdrv connection...\n");
    if (!InitializeDriver(kldbgDriverPath)) {
        wprintf(L"[DEBUG] Failed to initialize driver\n");
        return 1;
    }
    wprintf(L"[DEBUG] Driver connection established\n");

    if (objectPath != NULL) {
        // Single-shot mode: process the command-line path and exit
        ProcessObjectPath(objectPath);
    } else {
        // Interactive mode: read paths from stdin
        WCHAR inputBuffer[1024];

        wprintf(L"\n[Interactive mode] Enter \\Device\\... or \\Driver\\... paths. Type 'q' or 'quit' to exit.\n");

        for (;;) {
            wprintf(L"\n> ");
            fflush(stdout);

            if (fgetws(inputBuffer, ARRAYSIZE(inputBuffer), stdin) == NULL)
                break;

            // Strip trailing newline / carriage return
            SIZE_T len = wcslen(inputBuffer);
            while (len > 0 && (inputBuffer[len - 1] == L'\n' || inputBuffer[len - 1] == L'\r')) {
                inputBuffer[--len] = L'\0';
            }

            // Skip empty lines
            if (len == 0)
                continue;

            // Check for quit command
            if (_wcsicmp(inputBuffer, L"q") == 0 || _wcsicmp(inputBuffer, L"quit") == 0)
                break;

            ProcessObjectPath(inputBuffer);
        }
    }

    // Cleanup (will unload driver if we loaded it)
    CleanupDriver();
    return 0;
}
