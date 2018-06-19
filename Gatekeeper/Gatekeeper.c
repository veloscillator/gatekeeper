/*++

Module Name:

    Gatekeeper.c

Abstract:

    This is the main module of the Gatekeeper miniFilter driver.

Environment:

    Kernel mode

--*/

#include "gatekeeper.h"
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")



#define GATEKEEPER_TAG 'gtKP'


typedef struct {

	PFLT_FILTER Filter;

	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;


	//
	// TODO Lot's to say here.
	//

	// TODO Do we really need UNICODE_STRING?
	WCHAR DirectoryBufferDoNotUse[GATEKEEPER_MAX_BYTES]; // Don't directly reference. Managed by Directory.
	UNICODE_STRING Directory;
	EX_PUSH_LOCK DirectoryLock; // TODO Read-write nature of this is crucial.


	//
	// List of revoke items.
	//
	// TODO Limit on length of list?
	//
	
	LIST_ENTRY RevokeList;
	NPAGED_LOOKASIDE_LIST RevokeListFreeBuffers;
	EX_PUSH_LOCK RevokeListLock;
	


} GATEKEEPER_DATA;

typedef struct {

	LIST_ENTRY List;

	WCHAR RevokeItem[GATEKEEPER_MAX_BYTES];

} REVOKE_LIST, *PREVOKE_LIST;

GATEKEEPER_DATA gatekeeperData;


ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
GatekeeperInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
GatekeeperInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
GatekeeperInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
GatekeeperUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
GatekeeperInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
GatekeeperPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
GatekeeperPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

VOID
GatekeeperOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
GatekeeperPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
GatekeeperPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
GatekeeperDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

NTSTATUS
GatekeeperConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
);

VOID
GatekeeperDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

NTSTATUS
GatekeeperMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferSize) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferSize
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, GatekeeperUnload)
#pragma alloc_text(PAGE, GatekeeperInstanceQueryTeardown)
#pragma alloc_text(PAGE, GatekeeperInstanceSetup)
#pragma alloc_text(PAGE, GatekeeperInstanceTeardownStart)
#pragma alloc_text(PAGE, GatekeeperInstanceTeardownComplete)
#pragma alloc_text(PAGE, GatekeeperConnect)
#pragma alloc_text(PAGE, GatekeeperDisconnect)
#pragma alloc_text(PAGE, GatekeeperMessage)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      GatekeeperPreCreate,
      GatekeeperPostOperation },

    { IRP_MJ_CLOSE,
      0,
      GatekeeperPreOperation,
      GatekeeperPostOperation },

    { IRP_MJ_READ,
      0,
      GatekeeperPreOperation,
      GatekeeperPostOperation },

    { IRP_MJ_WRITE,
      0,
      GatekeeperPreOperation,
      GatekeeperPostOperation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    GatekeeperUnload,                           //  MiniFilterUnload

    GatekeeperInstanceSetup,                    //  InstanceSetup
    GatekeeperInstanceQueryTeardown,            //  InstanceQueryTeardown
    GatekeeperInstanceTeardownStart,            //  InstanceTeardownStart
    GatekeeperInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
GatekeeperInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
GatekeeperInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
GatekeeperInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperInstanceTeardownStart: Entered\n") );
}


VOID
GatekeeperInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;

	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING portName;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("Gatekeeper!DriverEntry: Entered\n"));


	//
	// Initialize gatekeeper data block.
	//

	RtlZeroMemory(&gatekeeperData, sizeof(gatekeeperData));

	
	FltInitializePushLock(&gatekeeperData.DirectoryLock);
	gatekeeperData.Directory.Buffer = gatekeeperData.DirectoryBufferDoNotUse;
	gatekeeperData.Directory.Length = 0;
	gatekeeperData.Directory.MaximumLength = sizeof(gatekeeperData.DirectoryBufferDoNotUse); // Length in bytes.

	ExInitializeNPagedLookasideList(
		&gatekeeperData.RevokeListFreeBuffers,
		NULL,
		NULL,
		POOL_NX_ALLOCATION,
		GATEKEEPER_MAX_BYTES,
		GATEKEEPER_TAG,
		0);
	InitializeListHead(&gatekeeperData.RevokeList);
	FltInitializePushLock(&gatekeeperData.RevokeListLock);

	

	try {

		//
		//  Register with FltMgr to tell it our callback routines
		//

		status = FltRegisterFilter(
			DriverObject,
			&FilterRegistration,
			&gatekeeperData.Filter);
		if (!NT_SUCCESS(status)) {
			leave;
		}

		
		//
		// Create port to communicate with gatectl.
		//

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(status)) {
			leave;
		}
		
		RtlInitUnicodeString(&portName, GATEKEEPER_PORT);

		InitializeObjectAttributes(
			&oa,
			&portName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			sd
		);

		status = FltCreateCommunicationPort(
			gatekeeperData.Filter,
			&gatekeeperData.ServerPort,
			&oa,
			NULL,
			GatekeeperConnect,
			GatekeeperDisconnect,
			GatekeeperMessage,
			1 // MaxConnections
		);
		FltFreeSecurityDescriptor(sd);
		if (!NT_SUCCESS(status)) {
			leave;
		}


		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(gatekeeperData.Filter);
		if (!NT_SUCCESS(status)) {
			leave;
		}



		//
		// TODO Temporary code to attach to C: volume. Change to support arbitrary volumes.
		//

		UNICODE_STRING volumeName = RTL_CONSTANT_STRING(L"C:");

		PFLT_VOLUME volume;
		status = FltGetVolumeFromName(gatekeeperData.Filter, &volumeName, &volume);
		FLT_ASSERT(NT_SUCCESS(status)); // TODO

		status = FltAttachVolume(gatekeeperData.Filter, volume, NULL, NULL);
		FLT_ASSERT(NT_SUCCESS(status)); // TODO

		FltObjectDereference(volume);



	} finally {
		if (!NT_SUCCESS(status)) {
			if (gatekeeperData.ServerPort != NULL) {
				FltCloseCommunicationPort(gatekeeperData.ServerPort);
				gatekeeperData.ServerPort = NULL;
			}
			if (gatekeeperData.Filter != NULL) {
				FltUnregisterFilter(gatekeeperData.Filter);
				gatekeeperData.Filter = NULL;
			}
		}
	}

    return status;
}

NTSTATUS
GatekeeperUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperUnload: Entered\n") );

	FltCloseCommunicationPort(gatekeeperData.ServerPort);

	FltDeletePushLock(&gatekeeperData.DirectoryLock);
	
	// TODO Empty revoke list.
	// TODO ExDeleteNPagedLookasideList(&gatekeeperData.RevokeListFreeBuffers);
	FltDeletePushLock(&gatekeeperData.RevokeListLock);

    FltUnregisterFilter(gatekeeperData.Filter);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
GatekeeperPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

	This routine is a pre-operation dispatch routine for this miniFilter.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
	opaque handles to this filter, instance, its associated volume and
	file object.

	CompletionContext - The context for the completion routine for this
	operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	// TODO
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN
GatekeeperWithinDirectory(
	_In_ PUNICODE_STRING FilePath,
	_In_ BOOLEAN IgnoreCase
)
/*++

Routine Description:

	Tells whether file is within the configured directory.

Arguments:

	FilePath - Full path to file.

	IgnoreCase - Is filesystem case insensitive?

Return Value:

	TRUE if file within configured directory. FALSE otherwise.

--*/
{
	size_t ii;
	BOOLEAN within = FALSE;

	FltAcquirePushLockShared(&gatekeeperData.DirectoryLock);


	if (gatekeeperData.Directory.Length != 0) {
		// TODO This is a pretty rudimentary way of performing this comparison. See nc!NcComparePath in
		// https://github.com/Microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/NameChanger
		for (ii = 0; TRUE; ii++) {
			if (ii >= gatekeeperData.Directory.Length) {
				// Consumed all of directory path without a mismatch. Directory is prefix of FilePath.
				within = TRUE;
				break;
			}
			if (ii >= FilePath->Length) {
				// TODO Think more about this. What if we are opening directory?
				within = FALSE;
				break;
			}

			if (IgnoreCase) {
				if (RtlUpcaseUnicodeChar(gatekeeperData.Directory.Buffer[ii]) !=
					RtlUpcaseUnicodeChar(FilePath->Buffer[ii])) {
					within = FALSE;
					break;
				}
			}
			else {
				if (gatekeeperData.Directory.Buffer[ii] !=
					FilePath->Buffer[ii]) {
					within = FALSE;
					break;
				}
			}
		}
	}


	FltReleasePushLock(&gatekeeperData.DirectoryLock);
	return within;
}

FLT_PREOP_CALLBACK_STATUS
GatekeeperPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK; // Assume we are NOT going to call our completion routine.
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN ignoreCase = TRUE;

    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperPreOperation: Entered\n") );

	if (FltObjects->FileObject == NULL) {
		status = STATUS_UNSUCCESSFUL;
		goto exit;
	}

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (!NT_SUCCESS(status)) {
		// Fail IO if we cannot get name.
		KdPrint(("Failed to get file name: 0x%x\n", status));
		returnStatus = FLT_PREOP_COMPLETE;
		goto exit;
	}

	FLT_ASSERT(Data->Iopb != NULL);
	ignoreCase = !BooleanFlagOn(Data->Iopb->OperationFlags, SL_CASE_SENSITIVE);

	if (GatekeeperWithinDirectory(&nameInfo->Name, ignoreCase)) {
		KdPrint(("Open %wZ\n", &nameInfo->Name));
	}




	if (wcsstr(nameInfo->Name.Buffer, L"gatekeepermatch")) {
		KdPrint(("Match: %wZ\n", &nameInfo->Name));
		status = STATUS_ACCESS_DENIED;
		returnStatus = FLT_PREOP_COMPLETE;
	}


exit:

	if (nameInfo != NULL) {
		FltReleaseFileNameInformation(nameInfo);
		nameInfo = NULL;
	}

	Data->IoStatus.Status = status;

	return returnStatus;
}

VOID
GatekeeperOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("Gatekeeper!GatekeeperOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
GatekeeperPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
GatekeeperPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
GatekeeperDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}


NTSTATUS
GatekeeperConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
)
/*++

Routine Description:
	
	Called when user-mode connects to server port.

Arguments:
 
	ClientPort - This is the pointer to the client port that
	will be used to send messages from the filter.
	ServerPortCookie - unused
	ConnectionContext - unused
	SizeofContext   - unused
	ConnectionCookie - unused

Return Value:
	
	NTSTATUS.

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	// TODO Don't have much of a reason to store this unless we're communicating back.
	// TODO Is there a potential race here?
	FLT_ASSERT(gatekeeperData.ClientPort == NULL); // Set MaxConnections to 1. Expect that to be enforced.
	gatekeeperData.ClientPort = ClientPort;

	return STATUS_SUCCESS;
}

VOID
GatekeeperDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description:
	
	Called when user <-> kernel mode connection is torn down.

Arguments:

	ConnectionCookie - unused

Return Value:

	None.

--*/
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);

	FltCloseClientPort(gatekeeperData.Filter, &gatekeeperData.ClientPort);
}

NTSTATUS
GatekeeperMessageSetDirectory(
	_In_ PGATEKEEPER_MSG Message
)
/*++

Routine Description:

	Sets global gatekeeper directory based on the given message after validating path.

Arguments:

	Message - Describes new directory.

Return Value:

	NTSTATUS.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	size_t length;
	HANDLE handle;
	PFILE_OBJECT fileObj;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING requestedName;
	IO_STATUS_BLOCK ioStatus;
	PFLT_FILE_NAME_INFORMATION nameInfo;

	FLT_ASSERT(Message->cmd == GatekeeperCmdDirectory);


	//
	// Validate string argument.
	//

	static_assert(GATEKEEPER_MAX_BYTES <= NTSTRSAFE_MAX_CCH, "restrictions of RtlStringCchLengthW");
	status = RtlStringCchLengthW(
		Message->data,
		sizeof(Message->data) / sizeof(Message->data[0]),
		&length);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	FLT_ASSERT(length + 1 <= GATEKEEPER_MAX_BYTES); // Via RtlStringCchLengthW return value.


	//
	// Validate existence of file and get absolute path.
	//

	requestedName.Buffer = Message->data;
	FLT_ASSERT(length <= MAXUSHORT); // TODO Should not be assert.
	requestedName.Length = (USHORT)length;
	requestedName.MaximumLength = (USHORT)length;

	InitializeObjectAttributes(
		&oa,
		&requestedName,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = FltCreateFileEx(
		gatekeeperData.Filter,
		NULL, // Instance
		&handle,
		&fileObj,
		0, // Desired access
		&oa,
		&ioStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		0, // Share access
		FILE_OPEN, // Open only. Don't create.
		FILE_DIRECTORY_FILE, // Create Options
		NULL,
		0,
		IO_IGNORE_SHARE_ACCESS_CHECK);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = FltGetFileNameInformationUnsafe(fileObj, NULL, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (!NT_SUCCESS(status)) {
		FltClose(handle);
		return status;
	}

	FltClose(handle);
	handle = NULL;

	if (nameInfo->Name.Length >= sizeof(gatekeeperData.DirectoryBufferDoNotUse)) {
		FltReleaseFileNameInformation(nameInfo);
		return STATUS_INVALID_PARAMETER;
	}


	//
	// Validation complete. Set directory.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.DirectoryLock);

	if (gatekeeperData.Directory.Length != 0) {
		// TODO Clear old info.
	}

	status = RtlStringCchCopyW(
		gatekeeperData.Directory.Buffer,
		sizeof(gatekeeperData.DirectoryBufferDoNotUse),
		nameInfo->Name.Buffer);
	FLT_ASSERT(NT_SUCCESS(status)); // Via validation above.
	FLT_ASSERT(nameInfo->Name.Length <= MAXUSHORT); // TODO Should not be assert.
	gatekeeperData.Directory.Length = (USHORT)nameInfo->Name.Length;

	FltReleasePushLock(&gatekeeperData.DirectoryLock);

	FltReleaseFileNameInformation(nameInfo);

	return status;
}

NTSTATUS
GatekeeperMessageRevoke(
	_In_ PGATEKEEPER_MSG Message
)
/*++

Routine Description:

	Add new item to revoke list.

Arguments:

	Message - Contains new item to add.

Return Value:

	NTSTATUS.

--*/
{
	NTSTATUS status;
	size_t length;
	PREVOKE_LIST newItem;

	//
	// Validate string argument.
	//

	static_assert(GATEKEEPER_MAX_BYTES <= NTSTRSAFE_MAX_CCH, "restrictions of RtlStringCchLengthW");
	status = RtlStringCchLengthW(
		Message->data,
		sizeof(Message->data) / sizeof(Message->data[0]),
		&length);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	FLT_ASSERT(length + 1 <= GATEKEEPER_MAX_BYTES); // Via RtlStringCchLengthW return value.


	//
	// Insert into revoke list.
	//

	// TODO Need sync?
	newItem = ExAllocateFromNPagedLookasideList(&gatekeeperData.RevokeListFreeBuffers);
	if (newItem == NULL) {
		return STATUS_NO_MEMORY;
	}

	status = RtlStringCchCopyW(newItem->RevokeItem, sizeof(newItem->RevokeItem) / sizeof(newItem->RevokeItem[0]), Message->data);
	FLT_ASSERT(NT_SUCCESS(status)); // Due to validateion.

	FltAcquirePushLockExclusive(&gatekeeperData.RevokeListLock);
	InsertHeadList(&gatekeeperData.RevokeList, &newItem->List);
	FltReleasePushLock(&gatekeeperData.RevokeListLock);

	return STATUS_SUCCESS;
}

NTSTATUS
GatekeeperMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferSize
)
/*++

Routine Description:

	Called whenever a user-mode applications wishes to communicate with this minifilter.

Arguments:

	ConnectionCookie - unused
	InputBuffer - A buffer containing input data, can be NULL if there
		is no input data.
	InputBufferSize - The size in bytes of the InputBuffer.
	OutputBuffer - A buffer provided by the application that originated
		the communication in which to store data to be returned to this
		application.
	OutputBufferSize - The size in bytes of the OutputBuffer.
	ReturnOutputBufferSize - The size in bytes of meaningful data
		returned in the OutputBuffer.

Return Value:

	NTSTATUS of processing the message.

 --*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(InputBufferSize);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(ReturnOutputBufferSize);

	GATEKEEPER_MSG message;


	//
	// Pull message into kernel memory.
	//

	if (InputBufferSize != sizeof(message)) {
		return STATUS_INVALID_PARAMETER;
	}

	try {
		RtlCopyMemory(&message, InputBuffer, InputBufferSize);
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}


	switch (message.cmd) {
	case GatekeeperCmdClear:
		// TODO
		break;
	case GatekeeperCmdDirectory:
		return GatekeeperMessageSetDirectory(&message);
	case GatekeeperCmdRevoke:
		return GatekeeperMessageRevoke(&message);
	case GatekeeperCmdUnrevoke:
		// TODO
		break;
	}




	// TODO Unimplemented.
	return STATUS_SUCCESS;
}