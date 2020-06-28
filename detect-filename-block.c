/*
 * coder : julietmike (https://github.com/jefrimustapa)
 * description :
 * - a simple minifilter driver example which will monitor
 *   specific directory in root volume.
 *
 * - if filename of files transfered into the directory contains
 *   pre-determined text, it will be blocked from being copied into
 *   the directory.
 */

#pragma warning(disable: 4996)
#pragma warning(disable: 4053)


#include <fltKernel.h>
#include <dontuse.h>
#include <Ntstrsafe.h>
#include <string.h>

#define MY_GITHUB "https://github.com/jefrimustapa"

#define MAX_PATH_LEN MAXIMUM_FILENAME_LENGTH

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define DBG_TRACE_ROUTINES            0x00000001
#define DBG_TRACE_OPERATION_STATUS    0x00000002


typedef struct {
	WCHAR* rootVolName;
	WCHAR* rootVolMount;
	WCHAR* monitorPath;
	WCHAR* monitorPathMount;
	ULONG traceFlag;
}GVAR, * PGVAR;

GVAR g = { NULL, NULL, NULL, NULL, DBG_TRACE_OPERATION_STATUS };

#define DRIVER_NAME "detect-filename-block"
#define MONITOR_FILENAME_TEXT L"JEFRI"

#define NULL_FN ((int)0)

#define DPE(ex_code) \
    (g.traceFlag > 0) ? \
    DbgPrint("[%d]%s!%s - exception, code:%d",__LINE__, DRIVER_NAME, __func__, ex_code) : \
    NULL_FN

#define DBG_PRINT(_dbgLevel, _format, ...) FlagOn(g.traceFlag, _dbgLevel) ? myDbgPrint(__FUNCTION__, __LINE__, _format, ##__VA_ARGS__) : NULL_FN
#define DBG_PRINT_ROUTINES(format, ...) DBG_PRINT(DBG_TRACE_ROUTINES, format, ##__VA_ARGS__)
#define DBG_PRINT_STAT(format, ...) DBG_PRINT(DBG_TRACE_OPERATION_STATUS, format, ##__VA_ARGS__)

#define DBG_BUFFER_SIZE 4000*sizeof(CHAR)

enum {
	ERROR_SUCCESS = 0,
	ERROR_ALLOC_MEM,
	ERROR_GET_VOLPROP,
	ERROR_EXCEPTION,
	ERROR_PARAM_NULL
};


/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

void myDbgPrint(CHAR* func, int line, CHAR* format, ...);
void getRootVolumeName(WCHAR** rootVolumeName);
int getFileName(WCHAR* filePath, WCHAR** fileName);
int getFilePath(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_CALLBACK_DATA Data,
	_Inout_ WCHAR** FilePath);
NTSTATUS getVolumeName(PFLT_VOLUME pVolume, WCHAR** volumeName);
NTSTATUS getMountDrive(WCHAR* pVolName, WCHAR** pMountDrive);
NTSTATUS denyAccessPreOp(PFLT_CALLBACK_DATA Data);

FLT_PREOP_CALLBACK_STATUS
handlePreSetInfo(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);
FLT_PREOP_CALLBACK_STATUS
handlePreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
driverInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
driverInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
driverInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
driverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
driverInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
driverPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);


FLT_POSTOP_CALLBACK_STATUS
driverPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);


EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, driverUnload)
#pragma alloc_text(PAGE, driverInstanceQueryTeardown)
#pragma alloc_text(PAGE, driverInstanceSetup)
#pragma alloc_text(PAGE, driverInstanceTeardownStart)
#pragma alloc_text(PAGE, driverInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	driverPreOperation,
	driverPostOperation },

	{ IRP_MJ_SET_INFORMATION,
	0,
	driverPreOperation,
	driverPostOperation },

	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	driverUnload,                           //  MiniFilterUnload

	driverInstanceSetup,                    //  InstanceSetup
	driverInstanceQueryTeardown,            //  InstanceQueryTeardown
	driverInstanceTeardownStart,            //  InstanceTeardownStart
	driverInstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};



NTSTATUS
driverInstanceSetup(
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
	NTSTATUS retStat = STATUS_NOT_SUPPORTED;
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	WCHAR* volumeName = NULL;
	try {
		try {

			if (getVolumeName(FltObjects->Volume, &volumeName) == STATUS_SUCCESS) {
				DBG_PRINT_STAT("volumeName:%S, rootVolName:%S\n", volumeName, g.rootVolName);
				if (wcscmp(volumeName, g.rootVolName) == 0) {
					//only attach to root drive
					retStat = STATUS_SUCCESS;
				}
			}

		}except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());
		}
	} finally {
		if (volumeName)
			ExFreePool(volumeName);
	}
	return retStat;
}


NTSTATUS
driverInstanceQueryTeardown(
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
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	DBG_PRINT(DBG_TRACE_ROUTINES,
		"driver!driverInstanceQueryTeardown: Entered\n");

	return STATUS_SUCCESS;
}


VOID
driverInstanceTeardownStart(
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

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	DBG_PRINT(DBG_TRACE_ROUTINES,
		"driver!driverInstanceTeardownStart: Entered\n");
}


VOID
driverInstanceTeardownComplete(
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

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	DBG_PRINT(DBG_TRACE_ROUTINES,
		"driver!driverInstanceTeardownComplete: Entered\n");
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
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

	UNREFERENCED_PARAMETER(RegistryPath);

	DBG_PRINT(DBG_TRACE_ROUTINES, "Entered\n");
	DBG_PRINT_STAT("Please visit my github:%s\n", MY_GITHUB);

	try {
		try {


			//initialize
			getRootVolumeName(&g.rootVolName);
			if (g.rootVolName != NULL) {
				g.monitorPath = (WCHAR*)ExAllocatePool(NonPagedPool, sizeof(WCHAR) * MAX_PATH_LEN);
				if (g.monitorPath != NULL) {
					swprintf(g.monitorPath, L"%s\\%S\\", g.rootVolName, DRIVER_NAME);
					DBG_PRINT_STAT("g.monitorPath:%S\n", g.monitorPath);
				}
			}

			getMountDrive(g.rootVolName, &g.rootVolMount);
			if (g.rootVolMount != NULL) {
				g.monitorPathMount = (WCHAR*)ExAllocatePool(NonPagedPool, sizeof(WCHAR) * MAX_PATH_LEN);
				if (g.monitorPathMount != NULL) {
					swprintf(g.monitorPathMount, L"%s\\%S\\", g.rootVolMount, DRIVER_NAME);
					DBG_PRINT_STAT("g.monitorPathMount:%S\n", g.monitorPathMount);
				}
			}

			//  Register with FltMgr to tell it our callback routines, 
			status = FltRegisterFilter(DriverObject,
				&FilterRegistration,
				&gFilterHandle);

			FLT_ASSERT(NT_SUCCESS(status));

			if (NT_SUCCESS(status)) {
				//  Start filtering i/o
				status = FltStartFiltering(gFilterHandle);

				if (!NT_SUCCESS(status)) {
					FltUnregisterFilter(gFilterHandle);
				}


			}
		}except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());

		}
	} finally {
		//cleanup here
	}
	return status;
}

NTSTATUS
driverUnload(
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
	Returns STATUS_SUCCESS. if does not return STATUS_SUCCESS minifilter will no unload

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();
	try {
		try {

			DBG_PRINT_STAT("Unloading\n");
			FltUnregisterFilter(gFilterHandle);

		}except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());

		}
	} finally {
		if (g.rootVolName != NULL)
			ExFreePool(g.rootVolName);
		if (g.monitorPath != NULL)
			ExFreePool(g.monitorPath);
		if (g.rootVolMount != NULL)
			ExFreePool(g.rootVolMount);
		if (g.monitorPathMount != NULL)
			ExFreePool(g.monitorPathMount);
	}

	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
handlePreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
	FLT_PREOP_CALLBACK_STATUS retStat = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	WCHAR* filePath = NULL;
	WCHAR* fileName = NULL;
	UNREFERENCED_PARAMETER(CompletionContext);

	try {
		try {
			//get filepath
			if (getFilePath(FltObjects, Data, &filePath) == ERROR_SUCCESS) {
				DBG_PRINT_ROUTINES("filePath: %S\n", filePath);
				//compare with monitored path
				if (wcsstr(filePath, g.monitorPath) != NULL) {
					DBG_PRINT_STAT("filePath: %S\n", filePath);

					//get filename
					if (getFileName(filePath, &fileName) == ERROR_SUCCESS) {
						DBG_PRINT_ROUTINES("fileName: %S\n", fileName);
						//check if filename contains our monitored text
						if (wcsstr(fileName, MONITOR_FILENAME_TEXT) != NULL) {
							//highest 8 bit represent the create dispotion. 
							//please refer to microsoft documentation here : https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create
							ULONG CreateDisposition = (Data->Iopb->Parameters.Create.Options & 0xff000000) >> 24;
							DBG_PRINT_STAT("CreateDisposition:%X\n", CreateDisposition);
							if (FlagOn(CreateDisposition, FILE_CREATE)) {
								DBG_PRINT_STAT("Block Create File!!!!\n");
								//set status access denied
								retStat = denyAccessPreOp(Data);
								leave;
							}

						}
					}
				}
			}
		}except(EXCEPTION_EXECUTE_HANDLER) {

		}
	} finally {
		if (filePath)
			ExFreePool(filePath);
		if (fileName)
			ExFreePool(fileName);
	}

	return retStat;
}

FLT_PREOP_CALLBACK_STATUS
handlePreSetInfo(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	/*	this is used to detect file moved into our monitored directory.
		file move is actually a rename of whole path.
	*/
) {
	FLT_PREOP_CALLBACK_STATUS retStat = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	WCHAR* pPathDst = NULL;
	WCHAR* pPathSrc = NULL;
	WCHAR* pFName = NULL;
	try {
		try {

			if (getFilePath(FltObjects, Data, &pPathSrc) == ERROR_SUCCESS) {
				if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
					DBG_PRINT_ROUTINES("rename path:%S\n", pPathSrc);
					PFILE_RENAME_INFORMATION fri = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
					if (fri) {
						size_t size = fri->FileNameLength + 2;
						pPathDst = (WCHAR*)ExAllocatePool(NonPagedPool, size);
						if (pPathDst) {

							RtlZeroMemory(pPathDst, size);
							RtlCopyMemory(pPathDst, fri->FileName, fri->FileNameLength);
							DBG_PRINT_ROUTINES("rename to : %S\n", pPathDst);

							if (wcsstr(pPathDst, g.monitorPathMount) != NULL) {
								if (getFileName(pPathDst, &pFName) == ERROR_SUCCESS) {
									DBG_PRINT_STAT("rename to : %S\n", pPathDst);
									if (wcsstr(pFName, MONITOR_FILENAME_TEXT) != NULL) {
										DBG_PRINT_STAT("BLOCK rename to : %S!!!\n", pPathDst);
										retStat = denyAccessPreOp(Data);
										leave;
									}
								}

							}

						}
					}
				}
			}


		}except(EXCEPTION_EXECUTE_HANDLER) {

		}
	} finally {
		if (pPathDst)
			ExFreePool(pPathDst);
		if (pPathSrc)
			ExFreePool(pPathSrc);
		if (pFName)
			ExFreePool(pFName);
	}

	return retStat;
}

/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
driverPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
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
	NTSTATUS status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);


	try {
		try {
			switch (Data->Iopb->MajorFunction) {
			case IRP_MJ_CREATE:
				status = handlePreCreate(Data, FltObjects, CompletionContext);
				break;
			case IRP_MJ_SET_INFORMATION:
				status = handlePreSetInfo(Data, FltObjects, CompletionContext);
				break;
			default:
				break;
			}
		}except(EXCEPTION_EXECUTE_HANDLER) {

		}
	} finally {

	}

	return status;
}

FLT_POSTOP_CALLBACK_STATUS
driverPostOperation(
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
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	DBG_PRINT(DBG_TRACE_ROUTINES, "driver!driverPostOperation: Entered\n");

	return FLT_POSTOP_FINISHED_PROCESSING;
}

// description:
//	deny access to IRP pre operation
// params: 
//	Data - PFLT_CALLBACK_DATA from IRP callback
NTSTATUS denyAccessPreOp(PFLT_CALLBACK_DATA Data) {
	try {
		try {
			Data->IoStatus.Information = 0;
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			FltSetCallbackDataDirty(Data);
		}except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());
		}
	} finally {
	}
	return FLT_PREOP_COMPLETE;
}

// get root volume.. volumes where your OS boots from
// params: 
//	rootVolumeNames - double pointer to allocate memory for result of volume name
void getRootVolumeName(WCHAR** rootVolumeName) {

	UNICODE_STRING rootPath;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ioStat;
	HANDLE RootHandle = NULL;
	NTSTATUS ntstat;
	PFILE_OBJECT pFileObj = NULL;
	ULONG retlen;
	PFLT_VOLUME pVol = NULL;
	POBJECT_NAME_INFORMATION pVolName = NULL;

	try {
		try {
			RtlInitUnicodeString(&rootPath, L"\\SystemRoot");
			InitializeObjectAttributes(&oa, &rootPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			ntstat = ZwCreateFile(&RootHandle, FILE_TRAVERSE, &oa, &ioStat, NULL, 0,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0);
			if (ntstat == STATUS_SUCCESS) {
				ntstat = ObReferenceObjectByHandle(RootHandle, 0, NULL, KernelMode, &pFileObj, NULL);
				if (ntstat == STATUS_SUCCESS) {
					DBG_PRINT_ROUTINES("pFileObj:%x\r\n", pFileObj);
					DBG_PRINT_ROUTINES("FileName:%S\r\n", pFileObj->FileName.Buffer);
					DBG_PRINT_ROUTINES("DeviceObject:%x\r\n", pFileObj->DeviceObject);

					ntstat = ObQueryNameString(pFileObj->DeviceObject, (POBJECT_NAME_INFORMATION)pVolName, 0, &retlen);
					DBG_PRINT_ROUTINES("ObQueryNameString return: %x, retlen: %d\r\n", ntstat, retlen);
					if (ntstat == STATUS_INFO_LENGTH_MISMATCH) {
						pVolName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, retlen);
						ntstat = ObQueryNameString(pFileObj->DeviceObject, (POBJECT_NAME_INFORMATION)pVolName, retlen, &retlen);
						DBG_PRINT_ROUTINES("ObQueryNameString return: %x, retlen: %d\r\n", ntstat, retlen);

						if (ntstat == STATUS_SUCCESS) {
							DBG_PRINT_ROUTINES("pVolName: %S\r\n", pVolName->Name.Buffer);
							*rootVolumeName = (WCHAR*)ExAllocatePool(NonPagedPool, sizeof(WCHAR) * MAX_PATH_LEN);
							if (*rootVolumeName != NULL)
								wcscpy(*rootVolumeName, pVolName->Name.Buffer);
						}
					}
				}
			}

		} except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());
		}
	} finally {
		if (pVol)
			FltObjectDereference(pVol);
		if (pFileObj)
			ObDereferenceObject(pFileObj);
		if (pVolName)
			ExFreePool(pVolName);
		if (RootHandle)
			ZwClose(RootHandle);
	}
}

// description:
//	print debug logs to debug consoles (use DbgView to view https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
// params: 
//	func - function name
//	line - line of the code snippet
//	format - string format
//	... - argument list for string format
// usage : 
//	**intended to be used not by itself. should be use with MACRO. please refer DBG_PRINT macro on top of the code.
void myDbgPrint(CHAR* func, int line, CHAR* format, ...) {
	CHAR* dbgBuffer = NULL;
	va_list marker;

	try {
		try {
			dbgBuffer = (CHAR*)ExAllocatePool(NonPagedPool, DBG_BUFFER_SIZE);
			if (dbgBuffer) {
				size_t wrlen = 0;
				sprintf(dbgBuffer, "[%d]%s!%s - ", line, DRIVER_NAME, func);
				wrlen = strlen(dbgBuffer);
				va_start(marker, format);
				vsprintf(dbgBuffer + wrlen, format, marker);
				va_end(marker);
				DbgPrint(dbgBuffer);
			}
		}except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());
		}
	} finally {
		if (dbgBuffer)
			ExFreePool(dbgBuffer);
	}
}

// description:
//	get filepath. first using FltGetFileNameInformation
//  if above failed. use Data & FltObjects to concatenate volume + filename
// params: 
//	FltObjects - PCFLT_RELATED_OBJECTS from IRP callback
//	Data - PFLT_CALLBACK_DATA from IRP callback
//	filepath - double pointer to allocate memory for result of filepath
// 
int getFilePath(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_CALLBACK_DATA Data,
	_Inout_ WCHAR** FilePath) {
	int iRet = ERROR_SUCCESS;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ReturnedLength;
	UCHAR VPBuffer[sizeof(FLT_VOLUME_PROPERTIES) + MAX_PATH_LEN];
	PFLT_VOLUME_PROPERTIES   VolumeProperties = (PFLT_VOLUME_PROPERTIES)VPBuffer;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	try {
		try {
			if (FltObjects != NULL) {
				if (Data != NULL) {
					if (FilePath != NULL) {
						//allocate memories
						*FilePath = (WCHAR*)ExAllocatePool(NonPagedPool, sizeof(WCHAR) * (MAX_PATH_LEN + 1));
						if (*FilePath == NULL) {
							DBG_PRINT(DBG_TRACE_ROUTINES, "Failed to allocated memory for FileName\r\n");
							iRet = ERROR_ALLOC_MEM;
							leave;
						}

						//try get the filename using fltgetfilename information first. if failed then get it via volume & fileobject
						status = FltGetFileNameInformation(Data,
							FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
							&nameInfo
						);

						if (!NT_SUCCESS(status)) {

							status = FltGetVolumeProperties(FltObjects->Volume,
								VolumeProperties,
								sizeof(VPBuffer),
								&ReturnedLength);

							if (!NT_SUCCESS(status)) {
								iRet = ERROR_GET_VOLPROP;
								leave;
							}

							//device/hardisk1
							RtlStringCchCopyNW(*FilePath, MAX_PATH_LEN, VolumeProperties->RealDeviceName.Buffer, VolumeProperties->RealDeviceName.MaximumLength / 2);

							if (FltObjects->FileObject->FileName.Length > 2) {
								LONG totalLen = (VolumeProperties->RealDeviceName.Length / 2) + (FltObjects->FileObject->FileName.Length / 2);
								if (totalLen > (MAX_PATH_LEN - 1))
									totalLen = MAX_PATH_LEN - 1;

								RtlStringCchCopyNW(*FilePath + (VolumeProperties->RealDeviceName.Length / 2),
									MAX_PATH_LEN - (VolumeProperties->RealDeviceName.Length / 2),
									FltObjects->FileObject->FileName.Buffer,
									FltObjects->FileObject->FileName.Length / 2);

								(*FilePath)[totalLen] = 0;
							}
						} else {
							LONG len2copy = nameInfo->Name.Length / 2;
							if (len2copy > MAX_PATH_LEN - 1)
								len2copy = MAX_PATH_LEN - 1;

							FltParseFileNameInformation(nameInfo);
							RtlStringCchCopyNW(*FilePath, MAX_PATH_LEN, nameInfo->Name.Buffer, len2copy);
							(*FilePath)[len2copy] = 0;
						}

					}
				}
			}

		} except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());
			iRet = ERROR_EXCEPTION;
		}
	} finally {
		if (nameInfo)
			FltReleaseFileNameInformation(nameInfo);

	}

	return iRet;
}

// description:
//	get filename from filepath. trace last '\' in filepath.
// params: 
//	filePath - pointer to filepath
//	fileName - double pointer to allocate memory for result of filepath
// 
int getFileName(WCHAR* filePath, WCHAR** fileName) {
	int retErr = ERROR_SUCCESS;

	try {
		try {
			if (filePath == NULL) {
				retErr = ERROR_PARAM_NULL;
				leave;
			}

			if (fileName) {
				WCHAR* p = NULL;
				p = wcsrchr(filePath, L'\\');
				if (p) {
					size_t size = sizeof(WCHAR) * wcslen(p);
					*fileName = (WCHAR*)ExAllocatePool(NonPagedPool, size);
					if (*fileName) {
						RtlZeroMemory(*fileName, size);
						wcscpy(*fileName, p);
						*fileName = _wcsupr(*fileName);
					}
				}
			} else {
				retErr = ERROR_PARAM_NULL;
			}
		}except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());

		}
	} finally {

	}
	return retErr;
}


// description:
//	get volume name given PFLT_VOLUME
// params: 
//	FltObjects - PCFLT_RELATED_OBJECTS from IRP callback
//	Data - PFLT_CALLBACK_DATA from IRP callback
//	filepath - double pointer to allocate memory for result of filepath
NTSTATUS getVolumeName(PFLT_VOLUME pVolume, WCHAR** volumeName) {
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING name;
	try {
		try {
			name.Buffer = NULL;
			ULONG size = 0;
			status = FltGetVolumeName(pVolume, NULL, &size);
			DBG_PRINT_ROUTINES("FltGetVolumeName return %x, size:%d\n", status, size);
			if (status == STATUS_BUFFER_TOO_SMALL) {
				*volumeName = (WCHAR*)ExAllocatePool(NonPagedPool, size + 2);
				name.Buffer = *volumeName;
				name.MaximumLength = (USHORT)size + 2;

				if (name.Buffer) {
					status = FltGetVolumeName(pVolume, &name, &size);
					DBG_PRINT_ROUTINES("FltGetVolumeName return %x\n", status);
					if (status == STATUS_SUCCESS) {
						DBG_PRINT_ROUTINES("guid: %wZ\n", &name);
					}
				}
			}


		}except(EXCEPTION_EXECUTE_HANDLER) {

		}
	} finally {
		if (status != STATUS_SUCCESS) {
			ExFreePool(*volumeName);
			*volumeName = NULL;
		}
	}
	return status;

}


// description:
//	get drive letter where volume is mounted
// params: 
//	pVolName - volume name. get using getVolumeName
//	pMountDrive - double pointer to allocate memory for result of mounted drive letter
NTSTATUS getMountDrive(WCHAR* pVolName, WCHAR** pMountDrive) {

	UNICODE_STRING path;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ioStat;
	HANDLE fileHandle = NULL;
	NTSTATUS ntstat = STATUS_SUCCESS;
	PFILE_OBJECT pFileObj = NULL;
	PFLT_VOLUME pVol = NULL;
	POBJECT_NAME_INFORMATION pObjNameInfo = NULL;

	__try {
		try {
			RtlInitUnicodeString(&path, pVolName);
			InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			ntstat = ZwCreateFile(&fileHandle, FILE_TRAVERSE, &oa, &ioStat, NULL, 0,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0);
			if (ntstat == STATUS_SUCCESS) {
				ntstat = ObReferenceObjectByHandle(fileHandle, 0, NULL, KernelMode, &pFileObj, NULL);
				if (ntstat == STATUS_SUCCESS) {
					DBG_PRINT_ROUTINES("pFileObj:%x\r\n", pFileObj);
					DBG_PRINT_ROUTINES("FileName:%S\r\n", pFileObj->FileName.Buffer);
					DBG_PRINT_ROUTINES("DeviceObject:%x\r\n", pFileObj->DeviceObject);

					ntstat = IoQueryFileDosDeviceName(pFileObj, &pObjNameInfo);
					DBG_PRINT_ROUTINES("IoQueryFileDosDeviceName return:%x, pObjNameInfo:%wZ\n", ntstat, &(pObjNameInfo->Name));
					if (ntstat == STATUS_SUCCESS) {
						int size = 0;

						size = pObjNameInfo->Name.MaximumLength + 1;
						*pMountDrive = ExAllocatePool(NonPagedPool, size);
						if (*pMountDrive != NULL) {
							RtlZeroMemory(*pMountDrive, size);
							RtlCopyMemory(*pMountDrive, pObjNameInfo->Name.Buffer, pObjNameInfo->Name.Length);
							DBG_PRINT_STAT("pMountDrive:%S\n", *pMountDrive);
						} else {
							ntstat = STATUS_MEMORY_NOT_ALLOCATED;
						}
					}

				}
			}

		} except(EXCEPTION_EXECUTE_HANDLER) {
			DPE(GetExceptionCode());
		}
	} finally {
		if (pVol)
			FltObjectDereference(pVol);
		if (pFileObj)
			ObDereferenceObject(pFileObj);
		if (fileHandle)
			ZwClose(fileHandle);
		if (pObjNameInfo)
			ExFreePool(pObjNameInfo);
	}

	return ntstat;
}