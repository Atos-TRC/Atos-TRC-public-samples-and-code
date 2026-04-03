// create_sd_driver.c — Create a software device node and bind an arbitrary driver to it,
// completely ignoring the INF layer.
//
// Flow:
//   1. SetupDiCreateDeviceInfoW + DIF_REGISTERDEVICE → PiCMCreateDevice → bare PDO
//   2. SetupDiSetDeviceRegistryPropertyW(SPDRP_SERVICE) → writes Enum\...\Service
//   3. Raw registry: find next free NNNN, create Control\Class\{ClassGUID}\NNNN + Enum\...\Driver
//   4. Restart the device node (disable + enable), triggering new driver load
//
// Usage: create_sd_bind_driver.exe <HardwareID> <DriverServiceName> <ClassGUID>
//   e.g. create_sd_bind_driver.exe FAKEHWID_2000 SampleDrv {7BFD0817-DC85-41C5-8A55-BF38B1A1667E}
//
// The driver service must already exist under
//   HKLM\SYSTEM\CurrentControlSet\Services\<DriverServiceName>
//
// Build:
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe create_sd_bind_driver.c /link setupapi.lib cfgmgr32.lib advapi32.lib

#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <stdio.h>

// Find the next available four-digit subkey index (0000, 0001, ...)
// under HKLM\SYSTEM\CurrentControlSet\Control\Class\{ClassGUID}.
// Returns the index, or 0 if the parent key doesn't exist yet.
static DWORD FindNextClassInstanceIndex(const wchar_t *classGuidStr)
{
    wchar_t parentPath[512];
    swprintf_s(parentPath, 512,
               L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", classGuidStr);

    HKEY hParent = NULL;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, parentPath, 0, KEY_READ, &hParent);
    if (rc != ERROR_SUCCESS)
        return 0;  // Key doesn't exist yet — 0000 is safe.

    DWORD maxIndex = 0;
    BOOL found = FALSE;
    wchar_t subkeyName[16];
    DWORD nameLen;

    for (DWORD i = 0; ; i++) {
        nameLen = _countof(subkeyName);
        rc = RegEnumKeyExW(hParent, i, subkeyName, &nameLen, NULL, NULL, NULL, NULL);
        if (rc != ERROR_SUCCESS)
            break;

        // Only consider four-digit numeric subkeys.
        if (nameLen == 4 && iswdigit(subkeyName[0]) && iswdigit(subkeyName[1])
                         && iswdigit(subkeyName[2]) && iswdigit(subkeyName[3])) {
            DWORD val = (DWORD)wcstoul(subkeyName, NULL, 10);
            found = TRUE;
            if (val >= maxIndex)
                maxIndex = val + 1;
        }
    }

    RegCloseKey(hParent);
    return found ? maxIndex : 0;
}

static BOOL ParseGuid(const wchar_t *str, GUID *guid)
{
    unsigned long d1;
    unsigned int d2, d3, d4, d5, d6, d7, d8, d9, d10, d11;
    int n = swscanf_s(str, L"{%8lx-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}",
                       &d1, &d2, &d3, &d4, &d5, &d6, &d7, &d8, &d9, &d10, &d11);
    if (n != 11) return FALSE;
    guid->Data1 = d1;
    guid->Data2 = (unsigned short)d2;
    guid->Data3 = (unsigned short)d3;
    guid->Data4[0] = (unsigned char)d4;
    guid->Data4[1] = (unsigned char)d5;
    guid->Data4[2] = (unsigned char)d6;
    guid->Data4[3] = (unsigned char)d7;
    guid->Data4[4] = (unsigned char)d8;
    guid->Data4[5] = (unsigned char)d9;
    guid->Data4[6] = (unsigned char)d10;
    guid->Data4[7] = (unsigned char)d11;
    return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 4) {
        fwprintf(stderr, L"Usage: %s <HardwareID> <DriverServiceName> <ClassGUID>\n", argv[0]);
        fwprintf(stderr, L"\nCreates a root-enumerated device node and binds the specified\n");
        fwprintf(stderr, L"driver service to it, bypassing INF-based driver installation.\n");
        fwprintf(stderr, L"\nThe ClassGUID must match the driver's device setup class.\n");
        fwprintf(stderr, L"Example:\n");
        fwprintf(stderr, L"  %s FAKEHWID DriverServiceName {7BFD0817-DC85-41C5-8A55-BF38B1A1667E}\n", argv[0]);
        return 1;
    }

    const wchar_t *hwid = argv[1];
    const wchar_t *serviceName = argv[2];
    const wchar_t *classGuidStr = argv[3];

    GUID classGuid;
    if (!ParseGuid(classGuidStr, &classGuid)) {
        fwprintf(stderr, L"Invalid ClassGUID format: %s\n", classGuidStr);
        fwprintf(stderr, L"Expected: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\n");
        return 1;
    }

    // Build REG_MULTI_SZ: hwid + double null terminator.
    wchar_t hwIdMultiSz[MAX_DEVICE_ID_LEN + 1] = { 0 };
    size_t len = wcslen(hwid);
    if (len >= MAX_DEVICE_ID_LEN) {
        fwprintf(stderr, L"Hardware ID too long (max %d chars).\n", MAX_DEVICE_ID_LEN - 1);
        return 1;
    }
    wcscpy_s(hwIdMultiSz, MAX_DEVICE_ID_LEN, hwid);
    hwIdMultiSz[len + 1] = L'\0';  // second null for MULTI_SZ

    // 1. Create an empty device info set with the driver's class GUID.
    HDEVINFO hDevInfo = SetupDiCreateDeviceInfoList(&classGuid, NULL);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"SetupDiCreateDeviceInfoList failed: %lu\n", GetLastError());
        return 1;
    }

    int ret = 1;
    SP_DEVINFO_DATA devInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
    wchar_t devInstId[MAX_DEVICE_ID_LEN] = { 0 };

    // 2. Create a new device node under the driver's class.
    //    Kernel path: PiCMCreateDevice → PiInitializeDevice → IopCreateRootEnumeratedDeviceObject
    if (!SetupDiCreateDeviceInfoW(hDevInfo, L"SoftwareDevice", &classGuid,
                                  NULL, NULL, DICD_GENERATE_ID, &devInfoData)) {
        fwprintf(stderr, L"SetupDiCreateDeviceInfoW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // 3. Set hardware ID on the devnode.
    if (!SetupDiSetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID,
                                           (const BYTE *)hwIdMultiSz,
                                           (DWORD)((len + 2) * sizeof(wchar_t)))) {
        fwprintf(stderr, L"Set SPDRP_HARDWAREID failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // 4. Register the device with PnP (materializes the PDO).
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, hDevInfo, &devInfoData)) {
        fwprintf(stderr, L"DIF_REGISTERDEVICE failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Get device instance ID (e.g. "ROOT\SOFTWAREDEVICE\0003") for direct registry access.
    if (!SetupDiGetDeviceInstanceIdW(hDevInfo, &devInfoData, devInstId,
                                     MAX_DEVICE_ID_LEN, NULL)) {
        fwprintf(stderr, L"SetupDiGetDeviceInstanceIdW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"Device node created: %s (DevInst=%lu)\n", devInstId, devInfoData.DevInst);

    // 5. Bind the driver: set the Service value directly.
    if (!SetupDiSetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_SERVICE,
                                           (const BYTE *)serviceName,
                                           (DWORD)((wcslen(serviceName) + 1) * sizeof(wchar_t)))) {
        fwprintf(stderr, L"Set SPDRP_SERVICE failed: %lu\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"Service bound: %s\n", serviceName);

    // Done with SetupDI — close the device info set NOW to commit any pending state
    // and avoid transacted registry rollback issues.
    SetupDiDestroyDeviceInfoList(hDevInfo);
    hDevInfo = INVALID_HANDLE_VALUE;

    // 6. Create the Driver (class) key using raw registry APIs.
    //    SetupDiCreateDevRegKey operates in a transacted context that may roll back
    //    if the installation isn't "completed". So we create the structure directly:
    //      a) Control\Class\{ClassGUID}\NNNN  (the class/driver key)
    //      b) Enum\...\Driver = "{ClassGUID}\NNNN"  (pointer from device to class key)
    {
        LONG rc;
        HKEY hKey = NULL;
        DWORD disp;

        // Find the next available instance index under this class GUID.
        DWORD classIdx = FindNextClassInstanceIndex(classGuidStr);

        // a) Create the class key: Control\Class\{ClassGUID}\NNNN
        wchar_t classKeyPath[512];
        swprintf_s(classKeyPath, 512,
                   L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s\\%04lu", classGuidStr, classIdx);

        rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, classKeyPath, 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
        if (rc != ERROR_SUCCESS) {
            fwprintf(stderr, L"Create class key failed: %lu\n", rc);
            fwprintf(stderr, L"  Path: %s\n", classKeyPath);
            goto cleanup;
        }

        RegSetValueExW(hKey, L"MatchingDeviceId", 0, REG_SZ,
                       (const BYTE *)hwid, (DWORD)((wcslen(hwid) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        hKey = NULL;

        wprintf(L"Class key created: %s\n", classKeyPath);

        // b) Write "Driver" value in the device's Enum key.
        wchar_t enumKeyPath[512];
        swprintf_s(enumKeyPath, 512,
                   L"SYSTEM\\CurrentControlSet\\Enum\\%s", devInstId);

        rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, enumKeyPath, 0, KEY_SET_VALUE, &hKey);
        if (rc != ERROR_SUCCESS) {
            fwprintf(stderr, L"Open Enum key failed: %lu\n", rc);
            fwprintf(stderr, L"  Path: %s\n", enumKeyPath);
            fwprintf(stderr, L"  (Enum tree may require SYSTEM privileges)\n");
            goto cleanup;
        }

        wchar_t driverValue[256];
        swprintf_s(driverValue, 256, L"%s\\%04lu", classGuidStr, classIdx);

        rc = RegSetValueExW(hKey, L"Driver", 0, REG_SZ,
                            (const BYTE *)driverValue,
                            (DWORD)((wcslen(driverValue) + 1) * sizeof(wchar_t)));
        if (rc != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            hKey = NULL;
            fwprintf(stderr, L"Set Driver value failed: %lu\n", rc);
            goto cleanup;
        }

        // c) Write ConfigFlags = 0.
        //    PiProcessNewDeviceNode reads ConfigFlags via _CmGetDeviceRegProp(0xb).
        //    If the value is missing, it sets problem 0x01 (CM_PROB_NOT_CONFIGURED)
        //    which activates DNF_HAS_PROBLEM, gating PipCallDriverAddDevice entirely.
        DWORD configFlags = 0;
        rc = RegSetValueExW(hKey, L"ConfigFlags", 0, REG_DWORD,
                            (const BYTE *)&configFlags, sizeof(configFlags));
        RegCloseKey(hKey);
        hKey = NULL;

        if (rc != ERROR_SUCCESS) {
            fwprintf(stderr, L"Set ConfigFlags failed: %lu\n", rc);
            goto cleanup;
        }

        wprintf(L"Driver value set: %s\n", driverValue);
        wprintf(L"ConfigFlags set: 0\n");
    }

    // 7. Trigger driver load.
    //    Use a disable/enable cycle to force PnP to rebuild the device stack
    //    using the existing registry configuration (Service + Driver key) — the same
    //    path PnP takes at boot for already-configured devices.
    {
        DEVINST devInst = 0;
        CONFIGRET cr = CM_Locate_DevNodeW(&devInst, devInstId, CM_LOCATE_DEVNODE_NORMAL);
        if (cr != CR_SUCCESS) {
            fwprintf(stderr, L"CM_Locate_DevNodeW failed: CR=0x%08lX\n", cr);
            ret = 2;
            goto cleanup;
        }

        wprintf(L"Restarting device (disable/enable cycle)...\n");

        cr = CM_Disable_DevNode(devInst, 0);
        if (cr != CR_SUCCESS) {
            fwprintf(stderr, L"CM_Disable_DevNode failed: CR=0x%08lX\n", cr);
            // Try enable anyway — device might not be in a state that needs disabling.
        }

        cr = CM_Enable_DevNode(devInst, 0);
        if (cr != CR_SUCCESS) {
            fwprintf(stderr, L"CM_Enable_DevNode failed: CR=0x%08lX\n", cr);
            ret = 2;
            goto cleanup;
        }

        wprintf(L"Device enabled. AddDevice should have been called.\n");
    }
    ret = 0;

cleanup:
    if (hDevInfo != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(hDevInfo);
    return ret;
}
