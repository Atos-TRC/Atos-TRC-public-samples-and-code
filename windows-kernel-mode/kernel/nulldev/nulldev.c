//
// nulldev.c - Creates a single unnamed device object via IoCreateDevice(NULL name).
// No dispatch routines, no symlinks. Just creates the object and sits there
// so we can examine it with !devobj in the debugger.
//
// Build:  build_nulldev.cmd
// Load:   sc create nulldev type= kernel binPath= C:\path\to\nulldev.sys
//         sc start nulldev
// Inspect: !drvobj \Driver\nulldev 2   -> get device object address
//          !devobj <devobj_addr>       -> check SecurityDescriptor address
//			!sd <sd_addr>				- see the SD
// Unload: sc stop nulldev & sc delete nulldev
//
#include <ntddk.h>
static PDEVICE_OBJECT g_Device = NULL;
DRIVER_INITIALIZE DriverEntry;
static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_Device)
        IoDeleteDevice(g_Device);
    DbgPrint("[nulldev] Unloaded\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    status = IoCreateDevice(DriverObject,
        0,                      // DeviceExtensionSize
        NULL,                   // DeviceName  (unnamed)
        FILE_DEVICE_UNKNOWN,
        0,                      // DeviceCharacteristics
        FALSE,                  // Exclusive
        &g_Device);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[nulldev] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }
	// If you don't see DbgPrint output, it might be filtered out. In such case run "ed nt!Kd_DEFAULT_Mask 0xf" in kd prompt.
    DbgPrint("[nulldev] Unnamed device created at %p\n", g_Device); 
    return STATUS_SUCCESS;
}
