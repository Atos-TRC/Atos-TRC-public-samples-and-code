//
// multidev.c - Minimal WDM driver creating two named CDOs with different SDs.
//
// Demonstrates that each named device object is an independent entry point
// from user mode, each with its own security descriptor.
//
// Device 1: \Device\MultiDevAdmin  - Admin + SYSTEM only
// Device 2: \Device\MultiDevPublic - Admin + SYSTEM + Everyone(RWX) + Restricted(RWX)
//
// Build:  build_multidev.cmd
// Load:   sc create multidev type= kernel binPath= C:\path\to\multidev.sys
//         sc start multidev
// Test:   open \\.\MultiDevAdmin and \\.\MultiDevPublic from user-mode
// Unload: sc stop multidev & sc delete multidev
//
// If you don't see DbgPrint output, it might be filtered out. In such case run "ed nt!Kd_DEFAULT_Mask 0xf" in kd prompt.
#include <ntddk.h>
#include <wdmsec.h>

// Symlinks for user-mode access
#define ADMIN_DEV_NAME    L"\\Device\\MultiDevAdmin"
#define ADMIN_LINK_NAME   L"\\DosDevices\\MultiDevAdmin"
#define PUBLIC_DEV_NAME   L"\\Device\\MultiDevPublic"
#define PUBLIC_LINK_NAME  L"\\DosDevices\\MultiDevPublic"

// SDDL strings
// Admin-only: SYSTEM=full, Admins=full
#define SDDL_ADMIN  L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
// Public: SYSTEM=full, Admins=full, Everyone=RWX, Restricted=RWX
#define SDDL_PUBLIC L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"

// Arbitrary device class GUID (required by IoCreateDeviceSecure)
// {7B5E5E7A-1234-5678-ABCD-112233445566}
//static const GUID MULTIDEV_GUID =
//    { 0x7b5e5e7a, 0x1234, 0x5678, { 0xab, 0xcd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } };

static PDEVICE_OBJECT g_AdminDevice  = NULL;
static PDEVICE_OBJECT g_PublicDevice = NULL;
static BOOLEAN        g_AdminLink    = FALSE;
static BOOLEAN        g_PublicLink   = FALSE;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

static NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("[multidev] IRP_MJ_CREATE\n");
    if (DeviceObject == g_AdminDevice)
        DbgPrint("[multidev] on AdminDevice\n");
    else
        DbgPrint("[multidev] on PublicDevice\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("[multidev] IRP_MJ_CLOSE\n");
    if (DeviceObject == g_AdminDevice)
        DbgPrint("[multidev] on AdminDevice\n");
    else
        DbgPrint("[multidev] on PublicDevice\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("[multidev] IRP_MJ_DEVICE_CONTROL\n");
    if (DeviceObject == g_AdminDevice)
        DbgPrint("[multidev] on AdminDevice\n");
    else
        DbgPrint("[multidev] on PublicDevice\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static void Cleanup(void)
{
    UNICODE_STRING linkName;

    if (g_AdminLink) {
        RtlInitUnicodeString(&linkName, ADMIN_LINK_NAME);
        IoDeleteSymbolicLink(&linkName);
    }
    if (g_PublicLink) {
        RtlInitUnicodeString(&linkName, PUBLIC_LINK_NAME);
        IoDeleteSymbolicLink(&linkName);
    }
    if (g_AdminDevice)
        IoDeleteDevice(g_AdminDevice);
    if (g_PublicDevice)
        IoDeleteDevice(g_PublicDevice);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[multidev] Unloading\n");
    Cleanup();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS        status;
    UNICODE_STRING  devName, linkName, sddl;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[multidev] DriverEntry\n");

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                         = DriverUnload;

    // --- Device 1: Admin-only ---
    RtlInitUnicodeString(&devName, ADMIN_DEV_NAME);
    RtlInitUnicodeString(&sddl, SDDL_ADMIN);

    status = IoCreateDeviceSecure(
        DriverObject,
        0,                          // DeviceExtensionSize
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                      // Exclusive
        &sddl,
        //&MULTIDEV_GUID,
		NULL,
        &g_AdminDevice);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[multidev] IoCreateDeviceSecure(Admin) failed: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&linkName, ADMIN_LINK_NAME);
    status = IoCreateSymbolicLink(&linkName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[multidev] IoCreateSymbolicLink(Admin) failed: 0x%08X\n", status);
        Cleanup();
        return status;
    }
    g_AdminLink = TRUE;

    // --- Device 2: Public (Admin + Everyone + Restricted) ---
    RtlInitUnicodeString(&devName, PUBLIC_DEV_NAME);
    RtlInitUnicodeString(&sddl, SDDL_PUBLIC);

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        //&MULTIDEV_GUID,
		NULL,
        &g_PublicDevice);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[multidev] IoCreateDeviceSecure(Public) failed: 0x%08X\n", status);
        Cleanup();
        return status;
    }

    RtlInitUnicodeString(&linkName, PUBLIC_LINK_NAME);
    status = IoCreateSymbolicLink(&linkName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[multidev] IoCreateSymbolicLink(Public) failed: 0x%08X\n", status);
        Cleanup();
        return status;
    }
    g_PublicLink = TRUE;

    DbgPrint("[multidev] Both devices created successfully\n");
    return STATUS_SUCCESS;
}
