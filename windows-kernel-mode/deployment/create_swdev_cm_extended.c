// create_swdev.c — Create a ROOT-enumerated software device node and install a driver via INF.
// Usage: create_swdev.exe <INF_PATH> <HardwareID>
// Build: cl create_swdev_cm_extended.c /link setupapi.lib newdev.lib

#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <newdev.h>
#include <stdio.h>

// Arbitrary class GUID for our software device.
// {62F9C741-B25A-46CE-B54C-9BCCCE08B6F2}
static const GUID SoftDevClassGuid =
    { 0x62f9c741, 0xb25a, 0x46ce, { 0xb5, 0x4c, 0x9b, 0xcc, 0xce, 0x08, 0xb6, 0xf2 } };

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 3) {
        fwprintf(stderr, L"Usage: %s <INF_PATH> <HardwareID>\n", argv[0]);
        return 1;
    }

    const wchar_t *infPath = argv[1];
    const wchar_t *hwid = argv[2];

    // Resolve INF to full path.
    wchar_t infFullPath[MAX_PATH] = { 0 };
    if (!GetFullPathNameW(infPath, MAX_PATH, infFullPath, NULL)) {
        fwprintf(stderr, L"GetFullPathNameW failed: %lu\n", GetLastError());
        return 1;
    }
    if (GetFileAttributesW(infFullPath) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"INF file not found: %s\n", infFullPath);
        return 1;
    }

    // Build a REG_MULTI_SZ: hwid + double null terminator.
    // MAX_DEVICE_ID_LEN (200) is the max single device ID length including null.
    wchar_t hwIdMultiSz[MAX_DEVICE_ID_LEN + 1] = { 0 };
    size_t len = wcslen(hwid);
    if (len >= MAX_DEVICE_ID_LEN) {
        fwprintf(stderr, L"Hardware ID too long (max %d chars).\n", MAX_DEVICE_ID_LEN - 1);
        return 1;
    }
    wcscpy_s(hwIdMultiSz, MAX_DEVICE_ID_LEN, hwid);
    hwIdMultiSz[len + 1] = L'\0';  // second null for MULTI_SZ

    // 1. Create an empty device info set for our class.
    HDEVINFO hDevInfo = SetupDiCreateDeviceInfoList(&SoftDevClassGuid, NULL);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"SetupDiCreateDeviceInfoList failed: %lu\n", GetLastError());
        return 1;
    }

    int ret = 1;
    SP_DEVINFO_DATA devInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };

    // 2. Create a new device node. Instance ID is auto-generated (ROOT\SoftwareDevice\0000...).
    if (!SetupDiCreateDeviceInfoW(hDevInfo, L"SoftwareDeviceCM", &SoftDevClassGuid,
                                  NULL, NULL, DICD_GENERATE_ID, &devInfoData)) {
        fwprintf(stderr, L"SetupDiCreateDeviceInfoW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // 3. Set the hardware ID on the new devnode.
    if (!SetupDiSetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID,
                                           (const BYTE *)hwIdMultiSz,
                                           (DWORD)((len + 2) * sizeof(wchar_t)))) {
        fwprintf(stderr, L"SetupDiSetDeviceRegistryPropertyW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // 4. Register the device with PnP (DIF_REGISTERDEVICE).
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, hDevInfo, &devInfoData)) {
        fwprintf(stderr, L"SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed: %lu\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"Device node created successfully for hardware ID: %s\n", hwid);

    // 5. Install the driver via INF (UpdateDriverForPlugAndPlayDevicesW).
    BOOL rebootRequired = FALSE;
    wprintf(L"Installing driver from: %s\n", infFullPath);
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, hwid, infFullPath,
                                            INSTALLFLAG_FORCE, &rebootRequired)) {
        fwprintf(stderr, L"UpdateDriverForPlugAndPlayDevicesW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"Driver installed successfully.\n");
    if (rebootRequired) {
        wprintf(L"Note: a reboot is required to complete installation.\n");
    }
    ret = 0;

cleanup:
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return ret;
}
