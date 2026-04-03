// Create a ROOT-enumerated software device node via Setup API.
// Usage: create_swdev.exe <HardwareID>
// Build: 
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe create_swdev_cm.c /link setupapi.lib newdev.lib

#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <newdev.h>
#include <stdio.h>

// System-reserved GUID for software device (https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use)
// {62F9C741-B25A-46CE-B54C-9BCCCE08B6F2}
static const GUID SoftDevClassGuid =
    { 0x62f9c741, 0xb25a, 0x46ce, { 0xb5, 0x4c, 0x9b, 0xcc, 0xce, 0x08, 0xb6, 0xf2 } };

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <HardwareID>\n", argv[0]);
        return 1;
    }
	// This is interesting:
	// https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdisetdeviceregistrypropertyw
	// "SPDRP_HARDWAREID or SPDRP_COMPATIBLEIDS can only be used when DeviceInfoData represents a root-enumerated device. For other devices, the bus driver reports hardware and compatible IDs when enumerating a child device after receiving IRP_MN_QUERY_ID."
	// This explains why we must use a root-enumerated device
    const wchar_t *hwid = argv[1];

    // Build a REG_MULTI_SZ: hwid + double null terminator.
    // MAX_DEVICE_ID_LEN (200) is the max single device ID length including null (defined in cfgmgr32.h)
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

	//The second argument to SetupDiCreateDeviceInfoW() is "a pointer to a NULL-terminated string that supplies either a full device instance ID (for example, "Root*PNP0500\0000") or a root-enumerated device ID without the enumerator prefix and instance identifier suffix (for example, "*PNP0500"). The root-enumerated device identifier can be used only if the DICD_GENERATE_ID flag is specified in the CreationFlags parameter."
    // 2. Create a new device node. Instance ID is auto-generated (ROOT\SoftwareDevice\0000...).
    if (!SetupDiCreateDeviceInfoW(hDevInfo, L"SoftwareDevice", &SoftDevClassGuid,
                                  NULL, NULL, DICD_GENERATE_ID, &devInfoData)) {
        fwprintf(stderr, L"SetupDiCreateDeviceInfoW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // 3. Set the hardware ID on the new devnode.
	// Creates structure in HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\ROOT\SOFTWAREDEVICE\0000
	/*
	HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\ROOT\SOFTWAREDEVICE\0000 with ClassGUID, HardwareID, Capabilities
	*/
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
    ret = 0;

cleanup:
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return ret;
}
