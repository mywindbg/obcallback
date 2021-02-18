/*++
 * Module Name: Main module for the Ob and Ps sample code
 *
 * Common Data Types:
 *
 * DeviceObject: A pointer to a DRIVER_OBJECT structure that represents the driver's WDM driver object.
 * Irp: The IRP structure is a partially opaque structure that represents an I/O request packet.
 *      Ref: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp
--*/

/**
 * @file tdriver.c
 * @author your name (you@domain.com)
 * @brief
 *  Interface:
 *      - DriverEntry
 *      - TdDeviceUnload
 *      - TdDeviceCreate
 *      - TdDeviceClose
 *      - TdDeviceCleanup
 *      - TdDeviceControl
 *      - TdCreateProcessNotifyRoutine2 - Callback when any process is created
 *
 * Static:
 *                                  // Called by TdDeviceControl
 *      - TdControlProtectName
 *      - TdControlUnprotect
 *
 * @version 0.1
 * @date 2021-02-17
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pch.h"
#include "tdriver.h"

static void PrintEmptyLine() {
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: ......\n");
}

static void PrintLine() {
    DbgPrint("=================================================================================================\n");
}

// Process notify routines.
BOOLEAN TdProcessNotifyRoutineSet2 = FALSE;

// allow filter the requested access
BOOLEAN TdbProtectName = FALSE;
BOOLEAN TdbRejectName = FALSE;

// Function declarations
DRIVER_INITIALIZE  DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)          DRIVER_DISPATCH TdDeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE)           DRIVER_DISPATCH TdDeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP)         DRIVER_DISPATCH TdDeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)  DRIVER_DISPATCH TdDeviceControl;

DRIVER_UNLOAD   TdDeviceUnload;

/**
 * @brief TdCreateProcessNotifyRoutine2
 *
 *  - If CreateInfo == NULL, the process is being terminated. Just return after logging.
 *
 *  - If CreateInfo->CommandLine == NULL, then we got nothing to do... just return.. :P
 *
 *  - If TdbProtectName is set to TRUE, invoke TdCheckProcessMatch() with arguments
 *
 *  - If TdbRejectName is set to TRUE, invoke TdCheckProcessMatch() with arguments;
 *          And Set CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
 *
 * @param Process [Inout]: A pointer to the EPROCESS structure that represents the process.
 *          Drivers can use the PsGetCurrentProcess and ObReferenceObjectByHandle routines
 *          to obtain a pointer to the EPROCESS structure for a process.
 * @param ProcessId [in]: The process ID of the process.
 * @param CreateInfo [in, out, optional]: A pointer to a PS_CREATE_NOTIFY_INFO structure
 *          that contains information about the new process.
 *          If this parameter is NULL, the specified process is exiting.
 *
 * @return VOID
 */
static VOID TdCreateProcessNotifyRoutine2 (_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (CreateInfo != NULL)
    {

        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) created, creator %Ix:%Ix\n"
            "    command line %wZ\n"
            "    file name %wZ (FileOpenNameAvailable: %d)\n",
            Process,
            (PVOID)ProcessId,
            (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
            (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
            CreateInfo->CommandLine,
            CreateInfo->ImageFileName,
            CreateInfo->FileOpenNameAvailable
        );

        // Search for matching process to protect only if filtering
        if (TdbProtectName) {
            if (CreateInfo->CommandLine != NULL)
            {
                Status = TdCheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);

                if (Status == STATUS_SUCCESS) {
                    DbgPrintEx (
                        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: PROTECTING process %p (ID 0x%p)\n",
                        Process,
                        (PVOID)ProcessId
                    );
                }
            }

        }

        // Search for matching process to reject process creation
        if (TdbRejectName) {
            if (CreateInfo->CommandLine != NULL)
            {
                Status = TdCheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);

                if (Status == STATUS_SUCCESS) {
                    DbgPrintEx (
                        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: REJECTING process %p (ID 0x%p)\n",
                        Process,
                        (PVOID)ProcessId
                    );

                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                }
            }

        }
    }
    else
    {
        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) destroyed\n",
            Process,
            (PVOID)ProcessId
        );
    }
}

/**
 * @brief DriverEntry
 *      Refer: https://docs.microsoft.com/en-us/windows-hardware/drivers/wdf/driverentry-for-kmdf-drivers
 *
 *  DriverEntry is the first driver-supplied routine that is called after a driver is loaded.
 *  It is responsible for initializing the driver.
 *
 *      1) Initialize global TdCallbacksMutex
 *      2) Create device object
 *          2.1) Set handler callbacks in the device object
 *      3) Create a symlink to device, into the win32 ( or dos ) namespace
 * 
 *      4) Use PsSetCreateProcessNotifyRoutineEx to register notification callbacks to process creation
 * 
 *      5) If any of above fails,
 *          5.1) Unregister call back for process creation
 *          5.2) Delete symlink and device
 *
 * @uses
 *      - KeInitializeGuardedMutex: To initialize global TdCallbacksMutex,
 *          which shall be used by other functions in this driver later.
 *      - IoCreateDevice: To create a virtual device
 *      - IoCreateSymbolicLink: To create symbolic link into Win32 namespace
 *      - PsSetCreateProcessNotifyRoutineEx: To register callback about new processes being created
 * @Globals:
 *      - Sets TdProcessNotifyRoutineSet2
 *
 * @param [In] DriverObject : A pointer to a DRIVER_OBJECT structure
 *                            that represents the driver's WDM driver object.
 * @param [In] RegistryPath : A pointer to a UNICODE_STRING structure
 *                            that specifies the path to the driver's Parameters key in the registry.

 * @return NTSTATUS : If the routine succeeds, it must return STATUS_SUCCESS.
 *                    Otherwise, it must return one of the error status values that are defined in ntstatus.h.
 */
NTSTATUS DriverEntry ( _In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath )
{
    NTSTATUS Status;
    UNICODE_STRING NtDeviceName = RTL_CONSTANT_STRING (TD_NT_DEVICE_NAME);
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING (TD_DOS_DEVICES_LINK_NAME);
    PDEVICE_OBJECT Device = NULL;
    BOOLEAN SymLinkCreated = FALSE;
    USHORT CallbackVersion;

    UNREFERENCED_PARAMETER (RegistryPath);

    PrintLine();
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: Driver loaded. Use ed nt!Kd_IHVDRIVER_Mask f (or 7) to enable more traces\n");

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: Get OB Filter Version");
    CallbackVersion = ObGetFilterVersion();

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObCallbackTest: DriverEntry: Callback version 0x%hx\n", CallbackVersion);
    PrintEmptyLine();

    //
    // Initialize globals.
    //

    DbgPrint("ObCallbackTest: Initialize Kernel Mutex.. Shall be used by other functions in this driver..\n");
    KeInitializeGuardedMutex (&TdCallbacksMutex);

    //
    // Create our device object.
    //

    /**
     * @brief IoCreateDevice
     *  Refer: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice
     *
     * DriverObject
     *      Pointer to the driver object for the caller.
     *      Each driver receives a pointer to its driver object in a parameter to its DriverEntry routine.
     *      WDM function and filter drivers also receive a driver object pointer in their AddDevice routines.
     *
     * DeviceExtensionSize
     *      Specifies the driver-determined number of bytes to be allocated for the device extension of the device object.
     *      The internal structure of the device extension is driver-defined.
     *      This memory shall be used to:
     *          1) Maintain device state information.
     *          2) Provide storage for any kernel-defined objects or other system resources, such as spin locks, used by the driver.
     *          3) Hold any data the driver must have resident and in system space to carry out its I/O operations.
     *
     * DeviceName
     *      Optionally points to a buffer containing a null-terminated Unicode string that names the device object.
     *      The string must be a full path name.
     *      WDM filter and function drivers do not name their device objects.
     *      For more information, see Named Device Objects.
     *
     */

    Status = IoCreateDevice (
        DriverObject,                 // pointer to driver object - Each driver receives a pointer to its driver object in a parameter to its DriverEntry routine.
        0,                            // device extension size
        &NtDeviceName,                // device name - Can be empty, but if its empty, it cannot have discretionary access control list (DACL) associated with it.
        FILE_DEVICE_UNKNOWN,          // device type
        0,                            // device characteristics
        FALSE,                        // not exclusive - If exclusive access to a device is enabled, only one handle to the device can be open at a time
        &Device);                     // returned device object pointer - Pointer to a variable that receives a pointer to the newly created DEVICE_OBJECT structure, allocated from nonpaged pool

    if (! NT_SUCCESS(Status))
    {
        goto Exit;
    }

    TD_ASSERT (Device == DriverObject->DeviceObject);
    DbgPrint("ObCallbackTest: IoCreateDevice - Success\n");

    //
    // Set dispatch routines.
    //

    DbgPrint("ObCallbackTest: Set major functions and driver unload modules\n");
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = TdDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = TdDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = TdDeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdDeviceControl;
    DriverObject->DriverUnload                         = TdDeviceUnload;

    //
    // Create a link in the Win32 namespace.
    //
    
    Status = IoCreateSymbolicLink (&DosDevicesLinkName, &NtDeviceName);

    if (! NT_SUCCESS(Status))
    {
        goto Exit;
    }
    DbgPrint("ObCallbackTest: IoCreateSymbolicLink - Success\n");
    DbgPrint("ObCallbackTest: TODO: Why should I create symbolic link? Can I skip it?\n");

    SymLinkCreated = TRUE;

    //
    // Set process create routines.
    //

    /**
     * @brief PsSetCreateProcessNotifyRoutineEx
     * Refer: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver
     *
     *  - PsSetCreateProcessNotifyRoutine   - notifies the driver about new/terminated processes
     *  - PsSetCreateProcessNotifyRoutineEx - notifies the driver about new processes being created, allows to kill them before they can run
     *  - PsSetCreateThreadNotifyRoutine    - notifies the driver about new/terminated threads
     *  - PsSetLoadImageNotifyRoutine       - notifies the driver about DLLs loaded by processes
     */

    DbgPrint("ObCallbackTest: PsSetCreateProcessNotifyRoutineEx - Add\n");
    Status = PsSetCreateProcessNotifyRoutineEx (
        TdCreateProcessNotifyRoutine2,
        FALSE
    );

    if (! NT_SUCCESS(Status))
    {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: PsSetCreateProcessNotifyRoutineEx(2) returned 0x%x\n", Status);
        goto Exit;
    }

    TdProcessNotifyRoutineSet2 = TRUE;

Exit:

    if (!NT_SUCCESS (Status))
    {
        if (TdProcessNotifyRoutineSet2 == TRUE)
        {
            Status = PsSetCreateProcessNotifyRoutineEx (
                TdCreateProcessNotifyRoutine2,
                TRUE
            );

            TD_ASSERT (Status == STATUS_SUCCESS);

            TdProcessNotifyRoutineSet2 = FALSE;
        }

        if (SymLinkCreated == TRUE)
        {
            IoDeleteSymbolicLink (&DosDevicesLinkName);
        }

        if (Device != NULL)
        {
            IoDeleteDevice (Device);
        }
    }

    PrintLine();
    return Status;
}

/**
 * @brief TdDeviceUnload
 *
 * @Description:
 *     This function handles driver unloading.
 *     All this driver needs to do is to
 *         delete the device object and
 *         delete the symbolic link between our device name and the Win32 visible name.
 *
 *      - Set into device object by the DriverEntry module
 *      - Called kernel, when the driver is unloaded.
 *
 * @Steps:
 *    1) Unregister process notify routines.
 *    2) remove filtering and remove any OB callbacks, using TdDeleteProtectNameCallback
 *    3) Delete the link from our device name to a name in the Win32 namespace.
 *    4) Delete our device object.
 *
 * @Uses:
 *      - PsSetCreateProcessNotifyRoutineEx: To unregister callback, if its registerd earlier.
 *      - TdDeleteProtectNameCallback: Unregister name protection
 *      - IoDeleteSymbolicLink: Delete symbolic link
 *      - IoDeleteDevice: Delete the virtual device
 *
 * @Globals:
 *      - TdbProtectName: unset
 *      - TdProcessNotifyRoutineSet2: Access
 *
 * @param [In] DriverObject : A pointer to a DRIVER_OBJECT structure
 *          that represents the driver's WDM driver object.
 */
VOID TdDeviceUnload ( _In_ PDRIVER_OBJECT DriverObject )
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING (TD_DOS_DEVICES_LINK_NAME);

    PrintLine();
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeviceUnload\n");

    //
    // Unregister process notify routines.
    //

    if (TdProcessNotifyRoutineSet2 == TRUE)
    {
        Status = PsSetCreateProcessNotifyRoutineEx (TdCreateProcessNotifyRoutine2, TRUE);
        TD_ASSERT (Status == STATUS_SUCCESS);
        TdProcessNotifyRoutineSet2 = FALSE;
    }

    // remove filtering and remove any OB callbacks
    TdbProtectName = FALSE;
    Status = TdDeleteProtectNameCallback();
    TD_ASSERT (Status == STATUS_SUCCESS);

    //
    // Delete the link from our device name to a name in the Win32 namespace.
    // Delete our device object.
    //
    Status = IoDeleteSymbolicLink (&DosDevicesLinkName);
    if (Status != STATUS_INSUFFICIENT_RESOURCES) {
        //
        // IoDeleteSymbolicLink can fail with STATUS_INSUFFICIENT_RESOURCES.
        //
    
        TD_ASSERT (NT_SUCCESS (Status));

    }
    IoDeleteDevice (DriverObject->DeviceObject);

    PrintLine();
}

/**
 * @brief TdDeviceIrpReset
 *  - Set IoStatus to STATUS_SUCCESS and Information to 0.
 *  - Return the IRP to I/O manager, through IoCompleteRequest, indicating all operations are completed.
 *
 * @Uses:
 *  - IoCompleteRequest: The IoCompleteRequest macro indicates that the caller has completed
 *      all processing for a given I/O request and is returning the given IRP to the I/O manager.
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
static NTSTATUS TdDeviceIrpReset (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
    PrintLine();
    UNREFERENCED_PARAMETER (DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    PrintLine();
    return STATUS_SUCCESS;
}

/**
 * @brief
 *
 * The operating system sends an IRP_MJ_CREATE request to open a handle to a file object or device object.
 *
 * Receipt of IRP_MJ_CLOSE request indicates that
 *      the last handle of the file object that is associated with the target device object has been closed and released.
 *      All outstanding I/O requests have been completed or canceled.
 *
 * Receipt of IRP_MJ_CLEANUP request indicates that
 *      the last handle for a file object that is associated with the target device object has been closed
 *      but, due to outstanding I/O requests, might not have been released.
 *
 * The operating system sends an IRP_MJ_DEVICE_CONTROL request,
 *      Any time following the successful completion of a create request.
 *
 *      TdDeviceCreate: This function handles the 'create' irp.
 *      TdDeviceClose: This function handles the 'close' irp.
 *      TdDeviceCleanup: This function handles the 'cleanup' irp.
 * 
 * @param DeviceObject 
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS TdDeviceCreate (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
    return TdDeviceIrpReset(DeviceObject, Irp);
}

NTSTATUS TdDeviceClose (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
    return TdDeviceIrpReset(DeviceObject, Irp);
}

NTSTATUS TdDeviceCleanup (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
    return TdDeviceIrpReset(DeviceObject, Irp);
}

/**
 * @brief TdControlProtectName
 *  - Get pointer to the IRP on the I/O stack
 *  - Get length of InputBufferLength from IRPStack
 *
 *  - Get pointer to Input argument from IRP's associated IRP
 *      This is going to be the pointer to TD_PROTECTNAME_INPUT structure, in our case
 *
 *  - Invoke TdProtectNameCallback with the name in the argument
 *  - Set TdbProtectName and TdbRejectName as per the operation mentioned in the argument
 *
 *  - Invoked on reception of TD_IOCTL_PROTECT_NAME_CALLBACK, by TdDeviceControl
 *
 * @Globals:
 *  - Set both TdbProtectName and TdbRejectName as per requested operation
 *
 * @Uses:
 *  - IoGetCurrentIrpStackLocation
 *  -
 *
 * @CalledBy:
 *  - TdDeviceControl
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
static NTSTATUS TdControlProtectName (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp)
{
    PrintLine();
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack = NULL;
    ULONG InputBufferLength = 0;
    PTD_PROTECTNAME_INPUT pProtectNameInput = NULL;

    UNREFERENCED_PARAMETER (DeviceObject);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdControlProtectName: Entering\n");

    // Get a pointer to the caller's I/O stack location in the specified IRP.
    IrpStack = IoGetCurrentIrpStackLocation (Irp);
    InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputBufferLength < sizeof (TD_PROTECTNAME_INPUT)) {
        Status = STATUS_BUFFER_OVERFLOW;
        goto Exit;
    }

    pProtectNameInput = (PTD_PROTECTNAME_INPUT)Irp->AssociatedIrp.SystemBuffer;
    Status = TdProtectNameCallback (pProtectNameInput);

    switch (pProtectNameInput->Operation) {
        case TDProtectName_Protect:
            // Begin filtering access rights
            TdbProtectName = TRUE;
            TdbRejectName = FALSE;
            break;
    
        case TDProtectName_Reject:
            // Begin reject process creation on match
            TdbProtectName = FALSE;
            TdbRejectName = TRUE;
            break;
    }

Exit:
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TD_IOCTL_PROTECTNAME: Status %x\n", Status);
    PrintLine();
    return Status;
}

/**
 * @brief TdControlUnProtect
 *  - Invoke TdDeleteProtectNameCallback
 *  - Set both TdbProtectName and TdbRejectName to FALSE
 *  - Invoked on TD_IOCTL_UNPROTECT_CALLBACK, by TdDeviceControl
 *
 * @Globals:
 *  - Set both TdbProtectName and TdbRejectName to FALSE
 *
 * @CalledBy:
 *  - TdDeviceControl
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
static NTSTATUS TdControlUnprotect (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER (DeviceObject);
    UNREFERENCED_PARAMETER (Irp);
    PrintLine();

    // do not filter requested access
    Status = TdDeleteProtectNameCallback();
    if (Status != STATUS_SUCCESS) {
        DbgPrintEx ( DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeleteProtectNameCallback:  status 0x%x\n", Status);
        }
    TdbProtectName = FALSE;
    TdbRejectName = FALSE;

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TD_IOCTL_UNPROTECT: exiting - status 0x%x\n", Status);

    PrintLine();
    return Status;
}

/**
 * @brief TdDeviceControl
 *
 *  - Get IRPStack and IOCTL code from the parameters in IRPStack
 *  - Act on received IOCTL
 *  - Complete the irp and return.
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS TdDeviceControl (IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp)
{
    PIO_STACK_LOCATION IrpStack;
    ULONG Ioctl;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER (DeviceObject);
    Status = STATUS_SUCCESS;
    PrintLine();

    // Get IRPStack and IOCTL code from the parameters in IRPStack
    IrpStack = IoGetCurrentIrpStackLocation (Irp);
    Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl: entering - ioctl code 0x%x\n", Ioctl);

    // Act on received IOCTL
    switch (Ioctl)
    {
    case TD_IOCTL_PROTECT_NAME_CALLBACK:

        Status = TdControlProtectName (DeviceObject, Irp);
        break;

    case TD_IOCTL_UNPROTECT_CALLBACK:

        Status = TdControlUnprotect (DeviceObject, Irp);
        break;


    default:
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "TdDeviceControl: unrecognized ioctl code 0x%x\n", Ioctl);
        break;
    }

    // Complete the irp and return.
    Irp->IoStatus.Status = Status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl leaving - status 0x%x\n", Status);
    PrintLine();
    return Status;
}
