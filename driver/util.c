/*++
Module Name: util.c
--*/

#include "pch.h"
#include "tdriver.h"

//
// TdSetCallContext
//
// Creates a call context object and stores a pointer to it
// in the supplied OB_PRE_OPERATION_INFORMATION structure.
//
// This function is called from a pre-notification. The created call context
// object then has to be freed in a corresponding post-notification using
// TdCheckAndFreeCallContext.
//

void TdSetCallContext (
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo,
    _In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
    PTD_CALL_CONTEXT CallContext;

    CallContext = (PTD_CALL_CONTEXT) ExAllocatePoolWithTag (
        PagedPool, sizeof(TD_CALL_CONTEXT), TD_CALL_CONTEXT_TAG
    );

    if (CallContext == NULL)
    {
        return;
    }

    RtlZeroMemory (CallContext, sizeof(TD_CALL_CONTEXT));

    CallContext->CallbackRegistration = CallbackRegistration;
    CallContext->Operation  = PreInfo->Operation;
    CallContext->Object     = PreInfo->Object;
    CallContext->ObjectType = PreInfo->ObjectType;

    PreInfo->CallContext = CallContext;
}

/**
 * @brief TdCheckAndFreeCallContext
 *
 *      1) Get CallContext from PostInfo
 *      2) Assert CallbackRegistration, Operation, Object and ObjectType are same b/w PostInfo and CallContext
 *      3) call ExFreePoolWithTag with the CallContext
 *
 * @param PostInfo - The OB_POST_OPERATION_INFORMATION structure provides information about a process or thread handle operation to an ObjectPostCallback routine.
 * @param CallbackRegistration
 */
void TdCheckAndFreeCallContext (
    _Inout_ POB_POST_OPERATION_INFORMATION PostInfo,
    _In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
    PTD_CALL_CONTEXT CallContext = (PTD_CALL_CONTEXT)PostInfo->CallContext;

    if (CallContext != NULL)
    {
        TD_ASSERT (CallContext->CallbackRegistration == CallbackRegistration);

    TD_ASSERT (CallContext->Operation  == PostInfo->Operation); // The type of handle operation. This member might be one of the following values:
    TD_ASSERT (CallContext->Object     == PostInfo->Object);    // A pointer to the process or thread object that is the target of the handle operation.
    TD_ASSERT (CallContext->ObjectType == PostInfo->ObjectType);// A pointer to the object type of the object. This type can be PsProcessType for a process or PsThreadType for a thread.

    /**
     * @brief Deallocates a block of pool memory allocated with the specified tag.
     *
     *  1) Specifies the beginning address of a block of pool memory allocated by either ExAllocatePoolWithTag or ExAllocatePoolWithQuotaTag.
     *  2) Specifies the tag value passed to ExAllocatePoolWithTag or ExAllocatePoolWithQuotaTag when the block of memory was originally allocated.
     */

        ExFreePoolWithTag (CallContext, TD_CALL_CONTEXT_TAG);
    }
}

