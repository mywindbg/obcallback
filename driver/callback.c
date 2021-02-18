
// Callback functions for Ob sample code tests.

/**
 * @file callback.c
 * @author your name (you@domain.com)
 * @brief
 *  Interface:
 *      - TdDeleteProtectNameCallback
 *      - TdProtectNameCallback
 *      - TdCheckProcessMatch
 * Static:
 *                                  // Sent to kernel, by TdProtectNameCallback
 *      - CBTdPreOperationCallback
 *      - CBTdPostOperationCallback
 * @version 0.1
 * @date 2021-02-17
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pch.h"
#include "tdriver.h"

//
// Globals
//

KGUARDED_MUTEX TdCallbacksMutex;
BOOLEAN bCallbacksInstalled = FALSE;


#define CB_PROCESS_TERMINATE 0x0001
#define CB_THREAD_TERMINATE  0x0001

//  The following are for setting up callbacks for Process and Thread filtering
PVOID pCBRegistrationHandle = NULL;

OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 }, { 0 } };
UNICODE_STRING CBAltitude = {0};
TD_CALLBACK_REGISTRATION CBCallbackRegistration = {0};

// Here is the protected process
WCHAR   TdwProtectName[NAME_SIZE+1] = {0};
PVOID   TdProtectedTargetProcess = NULL;
HANDLE  TdProtectedTargetProcessId = {0};


/**
 * @brief TdDeleteProtectNameCallback
 *
 *      1) Acquire kernel Mutex
 *      2) If any callbacks are registered, (i.e, if global bCallbacksInstalled is set to true)
 *          - UnRegister them by using ObUnRegisterCallbacks() and pCBRegistgrationHandle
 *          - set global bCallbacksInstalled to false
 *          - set global pCBRegistrationHandle to null
 *      3) Release kernel Mutex
 *
 * @return NTSTATUS
 */
NTSTATUS TdDeleteProtectNameCallback ()
{
    NTSTATUS Status = STATUS_SUCCESS;

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeleteProtectNameCallback entering\n");
    KeAcquireGuardedMutex (&TdCallbacksMutex);

    // if the callbacks are active - remove them
    if (bCallbacksInstalled == TRUE) {
        ObUnRegisterCallbacks(pCBRegistrationHandle);
        pCBRegistrationHandle = NULL;
        bCallbacksInstalled = FALSE;
    }

    KeReleaseGuardedMutex (&TdCallbacksMutex);
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeleteProtectNameCallback exiting  - status 0x%x\n", Status);

    return Status;
}


/**
 * @brief TdProtectNameCallback
 *
 *  - Acquire kernel mutex
 *  - Copy the name of process to be protected into global buffer
 *
 *  - If bCallbacksInstalled == TRUE, do nothing
 *
 *  - In global CBOperationRegistrations array, set
 *      - ObjectType = Process and thread,
 *      - Operations = CREATE and DUPLICATE
 *      - Pre/Post operation callbacks
 *
 *  - In global CBObRegistration structure, set
 *      - version, registration count, altitute and operation registrations
 *
 *  - Invoke ObRegisterCallbacks(), with CBObRegistration structure, and obtain handle to CB Registration (pCBRegistrationHandle)
 *  - This handle is required to unregister the callbacks
 *
 *  - Release kernel Mutex
 *
 * @param pProtectName
 * @return NTSTATUS
 */
NTSTATUS TdProtectNameCallback (_In_ PTD_PROTECTNAME_INPUT pProtectName)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (!pProtectName)
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: TdProtectNameCallback: name to protect/filter NULL pointer\n");
    else
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdProtectNameCallback: entering name to protect/filter %ls\n", pProtectName->Name);

    KeAcquireGuardedMutex (&TdCallbacksMutex);

    // Need to copy out the name and then set the flag to filter
    // This will allow process creation to watch for the process to be created and get the PID
    // and then prevent any other process from opening up that PID to terminate

    memcpy(TdwProtectName, pProtectName->Name, sizeof(TdwProtectName));

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: name copied     %ls\n", TdwProtectName);

    // Need to enable the OB callbacks once the process is matched to a newly created process, the callbacks will protect the process
    if (bCallbacksInstalled == FALSE) {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdProtectNameCallback: installing callbacks\n");

        // Setup the Ob Registration calls

        /**
         * @brief
         * typedef struct _OB_CALLBACK_REGISTRATION {
         *      USHORT                    Version;                      // The version of object callback registration that is requested. Drivers should specify OB_FLT_REGISTRATION_VERSION.
         *      USHORT                    OperationRegistrationCount;   // The number of entries in the OperationRegistration array.
         *      UNICODE_STRING            Altitude;                     // A Unicode string that specifies the altitude of the driver.
         *      PVOID                     RegistrationContext;          // The system passes the RegistrationContext value to the callback routine when the callback routine is run.
         *                                                              //      The meaning of this value is driver-defined.
         *      OB_OPERATION_REGISTRATION *OperationRegistration;       // A pointer to an array of OB_OPERATION_REGISTRATION structures.
         *                                                              // Each structure specifies ObjectPreCallback and ObjectPostCallback callback routines
         *                                                              //      and the types of operations that the routines are called for.
         * } OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;
         *
         *
         * typedef struct _OB_OPERATION_REGISTRATION {
         *      POBJECT_TYPE                *ObjectType;                // A pointer to the object type that triggers the callback routine.
         *                                                              //      - PsProcessType for process handle operations
         *                                                              //      - PsThreadType for thread handle operations
         *                                                              //      - ExDesktopObjectType for desktop handle operations.
         *
         *      OB_OPERATION                Operations;                 // One of the following
         *                                                              //      - OB_OPERATION_HANDLE_CREATE : A new process, thread, or desktop handle was or will be opened.
         *                                                              //      - OB_OPERATION_HANDLE_DUPLICATE : A process, thread, or desktop handle was or will be duplicated.
         *
         *      POB_PRE_OPERATION_CALLBACK  PreOperation;               // A pointer to an ObjectPreCallback routine. The system calls this routine before the requested operation occurs.
         *      POB_POST_OPERATION_CALLBACK PostOperation;              // A pointer to an ObjectPostCallback routine. The system calls this routine after the requested operation occurs.
         *
         *  }   OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;
         *
         */

        CBOperationRegistrations[0].ObjectType = PsProcessType;
        CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
        CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
        CBOperationRegistrations[0].PreOperation = CBTdPreOperationCallback;
        CBOperationRegistrations[0].PostOperation = CBTdPostOperationCallback;

        CBOperationRegistrations[1].ObjectType = PsThreadType;
        CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
        CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
        CBOperationRegistrations[1].PreOperation = CBTdPreOperationCallback;
        CBOperationRegistrations[1].PostOperation = CBTdPostOperationCallback;


        RtlInitUnicodeString (&CBAltitude, L"1000");

        CBObRegistration.Version                    = OB_FLT_REGISTRATION_VERSION;
        CBObRegistration.OperationRegistrationCount = 2;
        CBObRegistration.Altitude                   = CBAltitude;
        CBObRegistration.RegistrationContext        = &CBCallbackRegistration;
        CBObRegistration.OperationRegistration      = CBOperationRegistrations;


        // Registers a list of callback routines for thread, process, and desktop handle operations.
        Status = ObRegisterCallbacks (
            &CBObRegistration,
            &pCBRegistrationHandle       // save the registration handle to remove callbacks later
        );

        if (!NT_SUCCESS (Status))   {
            DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: installing OB callbacks failed  status 0x%x\n", Status);
            KeReleaseGuardedMutex (&TdCallbacksMutex); // Release the lock before exit
            goto Exit;
        }
        bCallbacksInstalled = TRUE;
    }

    KeReleaseGuardedMutex (&TdCallbacksMutex);
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdProtectNameCallback: name to protect/filter %ls\n", TdwProtectName);

Exit:
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdProtectNameCallback: exiting  status 0x%x\n", Status);
    return Status;
}


//
// TdCheckProcessMatch - function to test a command line to see if the process is to be protected
//
NTSTATUS TdCheckProcessMatch (
    _In_ PCUNICODE_STRING pustrCommand,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    WCHAR   CommandLineBuffer[NAME_SIZE + 1] = {0};    // force a NULL termination
    USHORT  CommandLineBytes = 0;

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCheckProcessMatch: entering\n");

    if (!pustrCommand || !pustrCommand->Buffer) {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: TdCheckProcessMatch: no Command line provided\n");
        Status = FALSE;
        goto Exit;
    }
    else {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCheckProcessMatch:              checking for %ls\n", TdwProtectName);
    }

    KeAcquireGuardedMutex (&TdCallbacksMutex);

    // Make sure that the CommandLineBuffer is NULL terminated
    if (pustrCommand->Length < (NAME_SIZE * sizeof(WCHAR)))
        CommandLineBytes = pustrCommand->Length;
    else
        CommandLineBytes = NAME_SIZE * sizeof(WCHAR);

    if (CommandLineBytes) {
        memcpy(CommandLineBuffer, pustrCommand->Buffer, CommandLineBytes);

        // now check if the process to protect is in the command line

        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCheckProcessMatch: command line %ls\n", CommandLineBuffer);

        if (NULL != wcsstr (CommandLineBuffer, TdwProtectName)) {
            DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCheckProcessMatch: match FOUND\n");

            // Set the process to watch
            TdProtectedTargetProcess = Process;
            TdProtectedTargetProcessId = ProcessId;

            Status = STATUS_SUCCESS;
        }
    }
    else {
        Status = FALSE;     // no command line buffer provided
    }

    KeReleaseGuardedMutex (&TdCallbacksMutex);

Exit:
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCheckProcessMatch: leaving    status  0x%x\n", Status);
    return Status;
}


//
// CBTdPreOperationCallback
//
static OB_PREOP_CALLBACK_STATUS CBTdPreOperationCallback (_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
    PTD_CALLBACK_REGISTRATION CallbackRegistration;

    ACCESS_MASK AccessBitsToClear     = 0;
    ACCESS_MASK AccessBitsToSet       = 0;
    ACCESS_MASK InitialDesiredAccess  = 0;
    ACCESS_MASK OriginalDesiredAccess = 0;

    PACCESS_MASK DesiredAccess = NULL;

    LPCWSTR ObjectTypeName = NULL;
    LPCWSTR OperationName = NULL;

    // Not using driver specific values at this time
    CallbackRegistration = (PTD_CALLBACK_REGISTRATION)RegistrationContext;
    TD_ASSERT (PreInfo->CallContext == NULL);

    // Only want to filter attempts to access protected process all other processes are left untouched

    if (PreInfo->ObjectType == *PsProcessType) {
        //
        // Ignore requests for processes other than our target process.
        //

        // if (TdProtectedTargetProcess != NULL && TdProtectedTargetProcess != PreInfo->Object)
        if (TdProtectedTargetProcess != PreInfo->Object)
        {
            goto Exit;
        }

        //
        // Also ignore requests that are trying to open/duplicate the current process.
        //

        if (PreInfo->Object == PsGetCurrentProcess()) {
            DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: ignore process open/duplicate from the protected process itself\n");
            goto Exit;
        }

        ObjectTypeName        = L"PsProcessType";
        AccessBitsToClear     = CB_PROCESS_TERMINATE;
        AccessBitsToSet       = 0;
    }
    else if (PreInfo->ObjectType == *PsThreadType)  {
        HANDLE ProcessIdOfTargetThread = PsGetThreadProcessId ((PETHREAD)PreInfo->Object);

        //
        // Ignore requests for threads belonging to processes other than our target process.
        //

        // if (CallbackRegistration->TargetProcess != NULL && CallbackRegistration->TargetProcessId != ProcessIdOfTargetThread)
        if (TdProtectedTargetProcessId != ProcessIdOfTargetThread)  {
            goto Exit;
        }

        //
        // Also ignore requests for threads belonging to the current processes.
        //

        if (ProcessIdOfTargetThread == PsGetCurrentProcessId()) {
            DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: ignore thread open/duplicate from the protected process itself\n");
            goto Exit;
        }

        ObjectTypeName        = L"PsThreadType";
        AccessBitsToClear     = CB_THREAD_TERMINATE;
        AccessBitsToSet       = 0;
    }
    else {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: unexpected object type\n");
        goto Exit;
    }

    switch (PreInfo->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        DesiredAccess = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
        OriginalDesiredAccess = PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;

        OperationName = L"OB_OPERATION_HANDLE_CREATE";
        break;

    case OB_OPERATION_HANDLE_DUPLICATE:
        DesiredAccess = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        OriginalDesiredAccess = PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

        OperationName = L"OB_OPERATION_HANDLE_DUPLICATE";
        break;

    default:
        TD_ASSERT (FALSE);
        break;
    }

    InitialDesiredAccess = *DesiredAccess;

    // Filter only if request made outside of the kernel
    if (PreInfo->KernelHandle != 1) {
        *DesiredAccess &= ~AccessBitsToClear;
        *DesiredAccess |=  AccessBitsToSet;
    }

    //
    // Set call context.
    //

    TdSetCallContext (PreInfo, CallbackRegistration);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: PROTECTED process %p (ID 0x%p)\n", TdProtectedTargetProcess, (PVOID)TdProtectedTargetProcessId);

    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: CBTdPreOperationCallback\n"
        "    Client Id:    %p:%p\n"
        "    Object:       %p\n"
        "    Type:         %ls\n"
        "    Operation:    %ls (KernelHandle=%d)\n"
        "    OriginalDesiredAccess: 0x%x\n"
        "    DesiredAccess (in):    0x%x\n"
        "    DesiredAccess (out):   0x%x\n",
        PsGetCurrentProcessId(),
        PsGetCurrentThreadId(),
        PreInfo->Object,
        ObjectTypeName,
        OperationName,
        PreInfo->KernelHandle,
        OriginalDesiredAccess,
        InitialDesiredAccess,
        *DesiredAccess
    );

Exit:

    return OB_PREOP_SUCCESS;
}

//
// TdPostOperationCallback
//

/**
 * @brief CBTdPostOperationCallback
 *
 *
 * @param RegistrationContext
 * @param PostInfo
 * @return VOID
 */
static VOID CBTdPostOperationCallback (_In_ PVOID RegistrationContext, _In_ POB_POST_OPERATION_INFORMATION PostInfo)
{
    PTD_CALLBACK_REGISTRATION CallbackRegistration = (PTD_CALLBACK_REGISTRATION)RegistrationContext;

    TdCheckAndFreeCallContext (PostInfo, CallbackRegistration);

    if (PostInfo->ObjectType == *PsProcessType) {
        //
        // Ignore requests for processes other than our target process.
        //

        if (CallbackRegistration->TargetProcess != NULL &&
            CallbackRegistration->TargetProcess != PostInfo->Object
        ) {
            return;
        }

        //
        // Also ignore requests that are trying to open/duplicate the current process.
        //

        if (PostInfo->Object == PsGetCurrentProcess())  {
            return;
        }
    }
    else if (PostInfo->ObjectType == *PsThreadType) {
        HANDLE ProcessIdOfTargetThread = PsGetThreadProcessId ((PETHREAD)PostInfo->Object);

        //
        // Ignore requests for threads belonging to processes other than our target process.
        //

        if (CallbackRegistration->TargetProcess   != NULL &&
            CallbackRegistration->TargetProcessId != ProcessIdOfTargetThread
        ) {
            return;
        }

        //
        // Also ignore requests for threads belonging to the current processes.
        //

        if (ProcessIdOfTargetThread == PsGetCurrentProcessId()) {
            return;
        }
    }
    else {
        TD_ASSERT (FALSE);
    }
}
