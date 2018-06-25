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


#define GATEKEEPER_TAG 'gtKP' // Tag memory allocations to detect leaks.


typedef struct {

	PFLT_FILTER Filter;

	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;


	//
	// Path to directory we're monitoring. Monitoring off if Directory.Length == 0.
	//

	WCHAR DirectoryBufferDoNotUse[GATEKEEPER_MAX_WCHARS]; // Don't directly reference. Managed by Directory.
	UNICODE_STRING Directory;
	EX_PUSH_LOCK DirectoryLock;


	//
	// List of revoke items.
	//
	
	LIST_ENTRY RevokeList;
	NPAGED_LOOKASIDE_LIST RevokeListFreeBuffers;
	EX_PUSH_LOCK RevokeListLock;
	

	//
	// File to log accesses to.
	//
	// TODO Keeping a handle open to this in a driver isn't the best. Do logs in user-mode or
	//      defered IO.
	//

	HANDLE LogHandle;
	UNICODE_STRING LogPath;
	WCHAR LogPathBufferDoNotUse[GATEKEEPER_MAX_WCHARS]; // Don't directly reference. Managed by LogPath.
	EX_PUSH_LOCK LogPathLock;

} GATEKEEPER_DATA;

typedef struct {

	LIST_ENTRY ListBlock;

	UNICODE_STRING Rule;
	WCHAR RevokeRuleBufferDoNotUse[GATEKEEPER_MAX_WCHARS]; // Don't access directly. Managed by Rule.

} REVOKE_RULE, *PREVOKE_RULE;


// Global data block for gatekeeper.
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

void
GatekeeperClear(void);

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

	// Stop incoming messages. Already assuming callbacks have been stopped.
	FltCloseCommunicationPort(gatekeeperData.ServerPort);

	GatekeeperClear();

	// Log file state.
	if (gatekeeperData.LogHandle != NULL) {
		ZwClose(gatekeeperData.LogHandle);
		gatekeeperData.LogHandle = NULL;
	}
	FltDeletePushLock(&gatekeeperData.LogPathLock);

	// Directory state.
	FltDeletePushLock(&gatekeeperData.DirectoryLock);
	
	// Revoke rules.
	ExDeleteNPagedLookasideList(&gatekeeperData.RevokeListFreeBuffers); // GatekeeperClear freed all nodes.
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
	
	// TODO This catches non-create operations. Handle revoke after create.


	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN
GatekeeperWithinDirectory(
	_In_ const PUNICODE_STRING FilePath,
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
	size_t charIndex;
	BOOLEAN within = FALSE;

	FltAcquirePushLockShared(&gatekeeperData.DirectoryLock);

	// Get length in WCHARS.
	FLT_ASSERT(FilePath->Length % sizeof(WCHAR) == 0);
	const size_t pathChars = FilePath->Length / sizeof(WCHAR);
	const size_t directoryChars = gatekeeperData.Directory.Length / sizeof(WCHAR);

	if (directoryChars == 0) {
		FltReleasePushLock(&gatekeeperData.DirectoryLock);
		return FALSE;
	}

	// TODO This is a pretty rudimentary way of performing this comparison. See nc!NcComparePath in
	// https://github.com/Microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/NameChanger
	for (charIndex = 0; TRUE; charIndex++) {

		if (charIndex >= directoryChars) {
			// Consumed all of directory path without a mismatch. Directory is prefix of FilePath.
			within = TRUE;
			break;
		}
		if (charIndex >= pathChars) {
			within = FALSE;
			break;
		}

		if (IgnoreCase) {
			if (RtlUpcaseUnicodeChar(gatekeeperData.Directory.Buffer[charIndex]) !=
				RtlUpcaseUnicodeChar(FilePath->Buffer[charIndex])) {
				within = FALSE;
				break;
			}
		}
		else {
			if (gatekeeperData.Directory.Buffer[charIndex] !=
				FilePath->Buffer[charIndex]) {
				within = FALSE;
				break;
			}
		}

	}

	FltReleasePushLock(&gatekeeperData.DirectoryLock);
	return within;
}

BOOLEAN
GatekeeperMatchRevokeRule(
	_In_ PCUNICODE_STRING Path,
	_In_ const PREVOKE_RULE Rule
)
/*++

Routine Description:

	Tries to match revoke rule to path by checking if rule is a substring of path.
	Case insensitive.

Arguments:

	Path - Path to apply rule to.

	Rule - Rule that defines match.

Return Value:

	TRUE if match found. FALSE otherwise.

--*/
{
	size_t charIndex;

	// Get length in characters.
	const size_t pathLen = Path->Length / sizeof(WCHAR);
	const size_t ruleLen = Rule->Rule.Length / sizeof(WCHAR);

	for (charIndex = 0; charIndex + ruleLen <= pathLen; charIndex++) {
		if (_wcsnicmp(&Path->Buffer[charIndex], Rule->Rule.Buffer, ruleLen) == 0) {
			return TRUE;
		}
	}

	return FALSE;
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

	IO_STATUS_BLOCK ioStatus;
	char logBuffer[GATEKEEPER_MAX_BYTES];
	size_t logBufferSizeChars;
	size_t logBufferRemainingChars;


    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Gatekeeper!GatekeeperPreOperation: Entered\n") );


	//
	// Get name of opened file and check if it's within our monitored directory.
	//

	if (gatekeeperData.Directory.Length == 0) {
		// Bail early if we're not monitoring anything.
		goto exit;
	}

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

	if (!GatekeeperWithinDirectory(&nameInfo->Name, ignoreCase)) {
		// Nothing to do for this file.
		goto exit;
	}

	
	//
	// This IO is within our directory. Log to file, it exists.
	//

	FltAcquirePushLockShared(&gatekeeperData.LogPathLock);

	if (gatekeeperData.LogHandle != NULL) {

		// Construct log message.
		logBufferSizeChars = sizeof(logBuffer) / sizeof(logBuffer[0]);
		status = RtlStringCchPrintfExA(
			logBuffer,
			logBufferSizeChars,
			NULL,
			&logBufferRemainingChars,
			0,
			"CREATE '%wZ'\r\n",
			&nameInfo->Name);
		FLT_ASSERT(status != STATUS_INVALID_PARAMETER);
		// TODO status == STATUS_BUFFER_OVERFLOW resulted in truncation. We're just letting this happen now.

		logBufferSizeChars = logBufferSizeChars - logBufferRemainingChars;

		status = ZwWriteFile(
			gatekeeperData.LogHandle,
			NULL,
			NULL,
			NULL, 
			&ioStatus,
			logBuffer,
			(ULONG)(logBufferSizeChars * sizeof(logBuffer[0])),
			NULL,
			NULL);
		if (!NT_SUCCESS(status)) {
			// TODO If logging fails, we continue for now. Should consider failing the IO.
		}

	}

	FltReleasePushLock(&gatekeeperData.LogPathLock); 


	//
	// Apply revoke rules.
	//

	FltAcquirePushLockShared(&gatekeeperData.RevokeListLock);
	
	BOOLEAN matched = FALSE;
	PLIST_ENTRY head = &gatekeeperData.RevokeList;
	PLIST_ENTRY prev = &gatekeeperData.RevokeList;
	PLIST_ENTRY current = prev->Flink;

	while (current != head) {

		PREVOKE_RULE rule = CONTAINING_RECORD(current, REVOKE_RULE, ListBlock);

		if (GatekeeperMatchRevokeRule(&nameInfo->Name, rule)) {
			matched = TRUE;
			break;
		}

		prev = current;
		current = prev->Flink;
	}

	FltReleasePushLock(&gatekeeperData.RevokeListLock);

	if (matched) {
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
	size_t lengthChars;
	size_t lengthBytes;
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

	status = RtlStringCchLengthW(
		Message->data,
		sizeof(Message->data) / sizeof(Message->data[0]),
		&lengthChars);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	lengthBytes = lengthChars * sizeof(WCHAR);
	FLT_ASSERT(lengthBytes + 1 <= GATEKEEPER_MAX_BYTES); // Via RtlStringCchLengthW return value.


	//
	// Validate existence of file and get absolute path.
	//

	requestedName.Buffer = Message->data;
	FLT_ASSERT(lengthBytes <= MAXUSHORT); // TODO Should not be assert.
	requestedName.Length = (USHORT)lengthBytes;
	requestedName.MaximumLength = (USHORT)lengthBytes;
	FLT_ASSERT(NT_SUCCESS(RtlUnicodeStringValidate(&requestedName)));

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
		FILE_LIST_DIRECTORY | FILE_TRAVERSE, // Desired access
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
	// Validation complete. Set directory. This will overwrite any previous directory.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.DirectoryLock);

	status = RtlStringCchCopyW(
		gatekeeperData.Directory.Buffer,
		sizeof(gatekeeperData.DirectoryBufferDoNotUse) / sizeof(WCHAR), // Size, in characters.
		nameInfo->Name.Buffer);
	FLT_ASSERT(NT_SUCCESS(status)); // Via validation above.
	FLT_ASSERT(nameInfo->Name.Length <= MAXUSHORT); // TODO Should not be assert.
	FLT_ASSERT(nameInfo->Name.Length % sizeof(WCHAR) == 0);
	gatekeeperData.Directory.Length = (USHORT)nameInfo->Name.Length;
	FLT_ASSERT(NT_SUCCESS(RtlUnicodeStringValidate(&gatekeeperData.Directory)));

	FltReleasePushLock(&gatekeeperData.DirectoryLock);

	FltReleaseFileNameInformation(nameInfo);

	return status;
}

void
GatekeeperClear(void)
/*++

Routine Description:

	Reset all state. Clears revoke rules and configured directory. State undefined
	(but valid) if interleaved with other requests. Does not clear log file info.

Arguments:

	None.

Return Value:

	None.

--*/
{
	PLIST_ENTRY pList;
	PREVOKE_RULE rule;
	HANDLE logHandle;


	//
	// First, clear revoke list.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.RevokeListLock);

	while (!IsListEmpty(&gatekeeperData.RevokeList)) {

		pList = RemoveHeadList(&gatekeeperData.RevokeList);

		rule = CONTAINING_RECORD(pList, REVOKE_RULE, ListBlock);
		ExFreeToNPagedLookasideList(&gatekeeperData.RevokeListFreeBuffers, rule); // TODO Don't hold lock around free.

	}

	FltReleasePushLock(&gatekeeperData.RevokeListLock);


	//
	// Clear directory.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.DirectoryLock);
	gatekeeperData.Directory.Length = 0;
	FltReleasePushLock(&gatekeeperData.DirectoryLock);


	//
	// Clear log file.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.LogPathLock);
	logHandle = gatekeeperData.LogHandle; // Close outside of lock.
	gatekeeperData.LogHandle = NULL;
	FltReleasePushLock(&gatekeeperData.LogPathLock);
	ZwClose(logHandle);
}

NTSTATUS
GatekeeperMessageRevoke(
	_In_ PGATEKEEPER_MSG Message
)
/*++

Routine Description:

	Creates a revoke rule. Does not detect duplicates.

Arguments:

	Message - Contains new item to add.

Return Value:

	NTSTATUS.

--*/
{
	NTSTATUS status;
	size_t lengthChars;
	size_t lengthBytes;
	PREVOKE_RULE newRule;

	FLT_ASSERT(Message->cmd == GatekeeperCmdRevoke);


	//
	// Validate string argument.
	//

	static_assert(GATEKEEPER_MAX_BYTES <= NTSTRSAFE_MAX_CCH, "restrictions of RtlStringCchLengthW");
	static_assert(GATEKEEPER_MAX_BYTES <= UNICODE_STRING_MAX_BYTES, "restrictions of UNICODE_STRING");

	status = RtlStringCchLengthW(
		Message->data,
		sizeof(Message->data) / sizeof(Message->data[0]),
		&lengthChars);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	lengthBytes = lengthChars * sizeof(WCHAR);
	FLT_ASSERT(lengthBytes + 1 <= GATEKEEPER_MAX_BYTES); // Via RtlStringCchLengthW return value.


	//
	// Create REVOKE_RULE structure.
	//

	newRule = ExAllocateFromNPagedLookasideList(&gatekeeperData.RevokeListFreeBuffers);
	if (newRule == NULL) {
		return STATUS_NO_MEMORY;
	}

	newRule->Rule.Buffer = newRule->RevokeRuleBufferDoNotUse;
	newRule->Rule.MaximumLength = sizeof(newRule->RevokeRuleBufferDoNotUse); // In bytes.

	status = RtlStringCchCopyW(newRule->Rule.Buffer, newRule->Rule.MaximumLength / sizeof(newRule->Rule.Buffer[0]), Message->data);
	FLT_ASSERT(NT_SUCCESS(status)); // Due to above validation.
	newRule->Rule.Length = (USHORT)lengthBytes;

	FLT_ASSERT(NT_SUCCESS(RtlUnicodeStringValidate(&newRule->Rule)));


	//
	// Insert into RevokeList.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.RevokeListLock);
	InsertHeadList(&gatekeeperData.RevokeList, &newRule->ListBlock);
	FltReleasePushLock(&gatekeeperData.RevokeListLock);

	return STATUS_SUCCESS;
}

NTSTATUS
GatekeeperMessageUnrevoke(
	_In_ PGATEKEEPER_MSG Message
)
/*++

Routine Description:

	Delete a revoke rule. Does not handle duplicates. Case sensitive.

Arguments:

	Message - Revoke rule to delete.

Return Value:

	NTSTATUS. STATUS_NOT_FOUND if no such rule.

--*/
{
	NTSTATUS status;
	size_t lengthChars;
	size_t lengthBytes;
	UNICODE_STRING ruleToDelete;

	FLT_ASSERT(Message->cmd == GatekeeperCmdUnrevoke);


	//
	// Validate string argument.
	//

	status = RtlStringCchLengthW(
		Message->data,
		sizeof(Message->data) / sizeof(Message->data[0]),
		&lengthChars);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	lengthBytes = lengthChars * sizeof(WCHAR);
	FLT_ASSERT(lengthBytes + 1 <= GATEKEEPER_MAX_BYTES); // Via RtlStringCchLengthW return value.

	ruleToDelete.Buffer = Message->data;
	ruleToDelete.MaximumLength = sizeof(Message->data);
	ruleToDelete.Length = (USHORT)lengthBytes;
	
	FltAcquirePushLockExclusive(&gatekeeperData.RevokeListLock);

	PLIST_ENTRY head = &gatekeeperData.RevokeList;
	PLIST_ENTRY prev = &gatekeeperData.RevokeList;
	PLIST_ENTRY current = prev->Flink;

	status = STATUS_NOT_FOUND;
	while (current != head) {

		PREVOKE_RULE rule = CONTAINING_RECORD(current, REVOKE_RULE, ListBlock);

		if (RtlEqualUnicodeString(&ruleToDelete, &rule->Rule, FALSE)) {
			// Remove from list.
			prev->Flink = current->Flink;
			current->Flink->Blink = prev;
			status = STATUS_SUCCESS;
			break;
		}

		prev = current;
		current = prev->Flink;
	}

	FltReleasePushLock(&gatekeeperData.RevokeListLock);

	return status;
}

NTSTATUS
GatekeeperMessageSetLogFile(
	_In_ PGATEKEEPER_MSG Message
)
/*++

Routine Description:

	Set file to log accesses to.

Arguments:

	Message - Log path information.

Return Value:

	NTSTATUS.

--*/
{
	NTSTATUS status;
	size_t lengthChars;
	size_t lengthBytes;
	HANDLE handle;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING requestedName;
	IO_STATUS_BLOCK ioStatus;
	HANDLE oldHandle = NULL;

	FLT_ASSERT(Message->cmd == GatekeeperCmdLogFile);


	//
	// Validate string argument.
	//

	status = RtlStringCchLengthW(
		Message->data,
		sizeof(Message->data) / sizeof(Message->data[0]),
		&lengthChars);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	lengthBytes = lengthChars * sizeof(WCHAR);
	FLT_ASSERT(lengthBytes + 1 <= GATEKEEPER_MAX_BYTES); // Via RtlStringCchLengthW return value.


	//
	// Attempt open/create of file.
	//

	requestedName.Buffer = Message->data;
	FLT_ASSERT(lengthBytes <= MAXUSHORT); // TODO Should not be assert.
	requestedName.Length = (USHORT)lengthBytes;
	requestedName.MaximumLength = (USHORT)lengthBytes;
	FLT_ASSERT(NT_SUCCESS(RtlUnicodeStringValidate(&requestedName)));

	InitializeObjectAttributes(
		&oa,
		&requestedName,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(
		&handle,
		FILE_APPEND_DATA, // Desired access
		&oa,
		&ioStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		return status;
	}


	//
	// New file successfully opened. Swap into global structure.
	//

	FltAcquirePushLockExclusive(&gatekeeperData.LogPathLock);

	oldHandle = gatekeeperData.LogHandle; // Close outside of lock.
	RtlCopyUnicodeString(&gatekeeperData.LogPath, &requestedName);
	gatekeeperData.LogHandle = handle;

	FltReleasePushLock(&gatekeeperData.LogPathLock);

	if (oldHandle != NULL) {
		ZwClose(oldHandle);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
GatekeeperMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferSize) PVOID OutputBuffer,
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
		GatekeeperClear();
		return STATUS_SUCCESS;
	case GatekeeperCmdDirectory:
		return GatekeeperMessageSetDirectory(&message);
	case GatekeeperCmdRevoke:
		return GatekeeperMessageRevoke(&message);
	case GatekeeperCmdUnrevoke:
		return GatekeeperMessageUnrevoke(&message);
	case GatekeeperCmdLogFile:
		return GatekeeperMessageSetLogFile(&message);
	default:
		return STATUS_INVALID_PARAMETER;
	}
}