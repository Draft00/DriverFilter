#include <fltKernel.h>
#include <dontuse.h>
#include <stdio.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)//2 6:30
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA)//2 7:30

#define BUFFER_SIZE 4096
#define LEN_MAX_PATH 560
/*************************************************************************
    Prototypes
*************************************************************************/

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
QUERY_INFO_PROCESS ZwQueryInformationProcess;

struct FileInfo
{
    WCHAR FileName[LEN_MAX_PATH];
    WCHAR IntLevel;
    int object; 
};
struct FileInfo FileInfoList[50];
unsigned int FileInfoListcount = 0;


EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsFilter1Unload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
FsFilter1OperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
FsFilter1DoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

NTSTATUS
ConfigFileParsing();

NTSTATUS 
DispatchPassThru(
    PDEVICE_OBJECT DeviceObject, 
    PIRP Irp
    );

NTSTATUS
DispatchDevCTL(
    PDEVICE_OBJECT DeviceObject, 
    PIRP Irp
    );

int FindInConfig(WCHAR* Path, int* flag);

void PcreateProcessNotifyRoutine(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
);

void PrintStringInFile(void);
EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilter1Unload)
#pragma alloc_text(PAGE, DispatchDevCTL)
#pragma alloc_text(PAGE, DispatchPassThru)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_READ,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },

    { IRP_MJ_WRITE,
      0,
      FsFilter1PreOperation,
      FsFilter1PostOperation },
      
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

    FsFilter1Unload,                           //  MiniFilterUnload

    NULL,            //  InstanceSetup
    NULL,            //  InstanceQueryTeardown
    NULL,           //  InstanceTeardownStart
    NULL,           //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

int FindInConfig(WCHAR* Path, int* flag)
{
    if (FileInfoListcount == 0)
        return 0;

    for (int i = 0; i < FileInfoListcount; i++)
    {
        if (wcscmp(Path, FileInfoList[i].FileName) == 0)
        {
            if (FileInfoList[i].object == 1)
            {
                *flag = 1;
            }

            if (FileInfoList[i].IntLevel == L'1')
                return 1;
            else if (FileInfoList[i].IntLevel == L'2')
                return 2;
            else if (FileInfoList[i].IntLevel == L'3')
                return 3;
            else if (FileInfoList[i].IntLevel == L'4')
                return 4;
            else if (FileInfoList[i].IntLevel == L'5')
                return 5;
            else return 6;
        }
    }

    return 0;
}

NTSTATUS
GetProcessImageName(
    PEPROCESS eProcess,
    PUNICODE_STRING* ProcessImageName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG returnedLength;
    HANDLE hProcess = NULL;

    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

    if (eProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    status = ObOpenObjectByPointer(eProcess,
        0, NULL, 0, 0, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
        return status;
    }

    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

        ZwQueryInformationProcess =
            (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (ZwQueryInformationProcess == NULL)
        {
            DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
            status = STATUS_UNSUCCESSFUL;
            goto cleanUp;
        }
    }

    /* Query the actual size of the process path */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        NULL, // buffer
        0,    // buffer size
        &returnedLength);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        DbgPrint("ZwQueryInformationProcess status = %x\n", status);
        goto cleanUp;
    }

    *ProcessImageName = ExAllocatePoolWithTag(NonPagedPoolNx, returnedLength, '2gat');

    if (ProcessImageName == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanUp;
    }
    /* Retrieve the process path from the handle to the process */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        *ProcessImageName,
        returnedLength,
        &returnedLength);

    if (!NT_SUCCESS(status)) ExFreePoolWithTag(*ProcessImageName, '2gat');

cleanUp:

    ZwClose(hProcess);
    return status;
}

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Myflt");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\Myfltlink");
PDEVICE_OBJECT DeviceObject = NULL;

VOID Unload(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = STATUS_SUCCESS;
    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(DeviceObject);

    //delete notification
    status = PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, TRUE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Already removed Notify\n");
    }
    KdPrint(("[Flt1]Driver unloaded successfully\r\n"));
}

NTSTATUS DispatchPassThru(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    //we need to know the major function type of this irp
    //first we need to get the io stack location
    PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    //from this stack location we can retrieve the major function type of irp
    switch (irpsp->MajorFunction)
    {
    case IRP_MJ_CREATE:
    {
       DbgPrint("DispThru create request\n");
        break;
    }
    case IRP_MJ_CLOSE:
    {
        DbgPrint("DispThru close request\n");
        break;
    }
    default:
    {
        status = STATUS_INVALID_PARAMETER;//indicate that driver doesn't support such request
        DbgPrint(("DispThru other request\n"));
        break;
    }
    }

    //we need to complete our request
    //first return value to IRP structure to indicate status of this operation
    Irp->IoStatus.Information = 0;//show how many bytes we successfully read or write in operation (0 as we didn't write anything)
    Irp->IoStatus.Status = status;

    //now call function to complete request
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

}

NTSTATUS DispatchDevCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS status_parse = STATUS_SUCCESS;

    //sending and receiving data
    //we need te retrieve the system buffer
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inlength = irpsp->Parameters.DeviceIoControl.InputBufferLength;//buffer len in sending function
    ULONG outlength = irpsp->Parameters.DeviceIoControl.OutputBufferLength;//buffer len in receiving function
    ULONG returnlength = 0;

    WCHAR* demo = L"sample returned from driver";

    switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
    {
    case DEVICE_SEND:
    {
        DbgPrint("Send device!\n");
        if (wcscmp(buffer, L"update") == 0)
        {
            status_parse = ConfigFileParsing();
            if (status_parse) {
                DbgPrint("[ERRFlt1]ConfigFileParsing\n");
            }
        }
        else if (wcscmp(buffer, L"setnotify") == 0)
        {
            status = PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, FALSE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[ERRFlt1]PsSetLoadImageNotifyRoutine failed. Status 0x%x\n", status);
            }
            else {
                DbgPrint("[Flt1]: PsSetLoadImageNotifyRoutine\n");
            }
        }
        else if (wcscmp(buffer, L"removenotify") == 0)
        {
            status = PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, TRUE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[ERRFlt1]PsSetLoadImageNotifyRoutine REMOVE failed. Status 0x%x\n", status);
            }
            else {
                DbgPrint("[Flt1]: PsSetLoadImageNotifyRoutine REMOVE\n");
            }
        }
        DbgPrint("recveive data is %ws\n", buffer);
        returnlength = (wcsnlen(buffer, 511) + 1) * 2;
        break;
    }
    case DEVICE_REC:
    {
        //need to check that buffer is null-terminated
        wcsncpy(buffer, demo, 511);
        DbgPrint("send data is %ws\n", demo);
        returnlength = (wcsnlen(buffer, 511) + 1) * 2;
        break;
    }
    default:
    {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = returnlength;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;

}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )

{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    DbgPrint("[Flt1]DriverEntry: Entered\n");

    DriverObject->DriverUnload = Unload;

    status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("creating device failed\n");
        return status;
    }
    //creating a symbolic link, as apps are not able to open the device we created here directly
    status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(("creating sym link failed\n"));
        //as we couldn't make link we need to delete the created device
        IoDeleteDevice(DeviceObject);
        return status;
    }

    //register dispatch funcs
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        //1 func for all major functions
        DriverObject->MajorFunction[i] = DispatchPassThru;
    }
    //different funcs for different major types
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDevCTL;
    //DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchCustom1;

    KdPrint(("[Flt1]Driver loaded successfully\r\n"));


    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
FsFilter1Unload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DbgPrint("[Flt1]FsFilter1Unload: Entered\n");

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}

/*************************************************************************
    MyFunk. For config file
*************************************************************************/

NTSTATUS ConfigFileParsing()
{
    DbgPrint("[Flt1]: ConfigFileParsing started!\n");

    NTSTATUS status;
    UNICODE_STRING UnicodeFileName;
    OBJECT_ATTRIBUTES FileAttributes;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatusBlock;
    //RtlInitUnicodeString(&UnicodeFileName, L"\\Device\\HarddiskVolume2\\Users\\Sergey\\Desktop\\config.txt");
    RtlInitUnicodeString(&UnicodeFileName, L"\\Device\\HarddiskVolume2\\Users\\Sergey\\Desktop\\config.csv");
    InitializeObjectAttributes(&FileAttributes, &UnicodeFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    status = ZwCreateFile(&Handle,
        GENERIC_READ,
        &FileAttributes, 
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    //DbgPrint("Start memset\n");

    memset(FileInfoList, 0, sizeof(struct FileInfo)*50);

    //DbgPrint("Memset ok!\n");

    if (status == STATUS_SUCCESS)
    {
        LARGE_INTEGER byteOffset;
        byteOffset.LowPart = 0;
        byteOffset.HighPart = 0;
        status = ZwReadFile(Handle, NULL, NULL, NULL, &IoStatusBlock,
            buffer, BUFFER_SIZE, &byteOffset, NULL);

        if (status == STATUS_SUCCESS)
        {
            FileInfoListcount = 0;
            DbgPrint("BUFFER: %s", buffer);
            
            unsigned int i = 0, index_in_filename = 0;
            while (buffer[i] != 0)
            {
                while (buffer[i] != ',') {
                    FileInfoList[FileInfoListcount].FileName[index_in_filename] = buffer[i];
                    i++; index_in_filename++;
                }
                i++; //skip ','
                if (buffer[i] == '1')
                {
                    FileInfoList[FileInfoListcount].object = 1;
                }
                else if ((buffer[i] == '0'))
                {
                    FileInfoList[FileInfoListcount].object = 0;
                }
                i += 2;
                
                index_in_filename = 0;
                FileInfoList[FileInfoListcount].IntLevel = buffer[i];
                DbgPrint("Name: %ws, IntLvl: %wc, obj: %d\n", FileInfoList[FileInfoListcount].FileName, FileInfoList[FileInfoListcount].IntLevel, FileInfoList[FileInfoListcount].object);
                FileInfoListcount++;
                i += 3; //skip number and '\n' (seems it's 2 byte??)
                //DbgPrint("Buffer: %c, %d\n", buffer[i], buffer[i]);
                //DbgPrint("Buffer: %c, %d\n", buffer[i + 1], buffer[i + 1]);
            }
            
            //return STATUS_SUCCESS;
            
        }
        else
        {
            DbgPrint("[ERRFlt1]: ZWReadfile\n");
            ZwClose(Handle);
            return !STATUS_SUCCESS;
        }
    }
    else
    {
        DbgPrint("[ERRFlt1]: ZWCreatefile\n");
        ZwClose(Handle);
        return !STATUS_SUCCESS;
    }
    ZwClose(Handle);
    return STATUS_SUCCESS;
}

char str[2048] = { 0 };
void PcreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    LARGE_INTEGER SystemTime;
    TIME_FIELDS TimeFields;

    KeQuerySystemTime(&SystemTime);
    RtlTimeToTimeFields(&SystemTime, &TimeFields);
    PUNICODE_STRING processName = NULL;
    NTSTATUS status;
    status = GetProcessImageName(PsGetCurrentProcess(), &processName);

    memset(str, 0, 2048);
    if (Create) {
        sprintf(str, "Created Process Name: %ws Process Id: %u Time: %i : %i : %i\n", processName->Buffer, PtrToInt(ProcessId), TimeFields.Hour, TimeFields.Minute, TimeFields.Second);
    }
    else sprintf(str, "Deleted Process Name: %ws Process Id: %u Time: %i : %i : %i\n", processName->Buffer, PtrToInt(ProcessId), TimeFields.Hour, TimeFields.Minute, TimeFields.Second);
    DbgPrint("[Flt1]Some process del or create\n");
    PrintStringInFile();

}

void PrintStringInFile()
{
    NTSTATUS status;
    UNICODE_STRING UnicodeFileName;
    OBJECT_ATTRIBUTES FileAttributes;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatusBlock;
    RtlInitUnicodeString(&UnicodeFileName, L"\\Device\\HarddiskVolume2\\Users\\Sergey\\Desktop\\log.txt");
    InitializeObjectAttributes(&FileAttributes, &UnicodeFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;


    status = ZwCreateFile(&Handle,
        FILE_APPEND_DATA,
        &FileAttributes, &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (status == STATUS_SUCCESS)
    {
        ULONG buffer_size = (ULONG)strlen(str);
        status = ZwWriteFile(Handle, NULL, NULL, NULL, &IoStatusBlock,
            str, buffer_size, NULL, NULL);
        //GlobalByteOffset.LowPart += buffer_size;
        if (status == STATUS_SUCCESS)
            DbgPrint("[Flt1]: PrintStringInFile successfully!\n");
        else
            DbgPrint("[ERRFlt1]: PrintStringInFile (ZwWriteFile) failed!\n");
    }
    else
        DbgPrint("[ERRFlt1]: PrintStringInFile (ZwCreateFile) failed!\n");

    ZwClose(Handle);
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    WCHAR Name[LEN_MAX_PATH] = { 0 };
    WCHAR NameProcess[LEN_MAX_PATH] = { 0 };
    int IntLvlFile = 0, IntLvlProcess = 0;
    int flag_object = 0;

    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    //DbgPrint("[Flt1]PreOperation: Entered\n");

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status))
    {
        status = FltParseFileNameInformation(FileNameInfo);
        if (NT_SUCCESS(status))
        {
            if (FileNameInfo->Name.MaximumLength < LEN_MAX_PATH)
            {
                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);

                flag_object = 0;
                IntLvlFile = FindInConfig(Name, &flag_object);
                if (IntLvlFile && flag_object)
                {
                    PUNICODE_STRING processName = NULL;
                    GetProcessImageName(PsGetCurrentProcess(), &processName);
                    RtlCopyMemory(NameProcess, processName->Buffer, processName->MaximumLength);
                    DbgPrint("Name od pr: %ws\n", NameProcess);
                    IntLvlProcess = FindInConfig(NameProcess, &flag_object);
                    if (IntLvlProcess)
                    {
                        DbgPrint("IntLvl %d for process: %ws\n", IntLvlProcess, processName->Buffer);
                        if (IntLvlFile > IntLvlProcess)
                        {
                            DbgPrint("Open file %ws blocked for process %ws\n", Name, processName->Buffer);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            Data->IoStatus.Information = 0;
                           
                            FltReleaseFileNameInformation(FileNameInfo);
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                    else if (IntLvlFile > 3 && flag_object)
                    {
                        //PUNICODE_STRING processName = NULL;
                       // GetProcessImageName(PsGetCurrentProcess(), &processName);
                        //RtlCopyMemory(NameProcess, processName->Buffer, processName->MaximumLength);
                       // if (wcscmp(NameProcess, L"\\Device\\HarddiskVolume2\\Windows\\explorer.exe") != 0)
                       // {
                            DbgPrint("Open file %ws blocked for process %ws\n", Name, processName->Buffer);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            Data->IoStatus.Information = 0;
                            FltReleaseFileNameInformation(FileNameInfo);
                            return FLT_PREOP_COMPLETE;
                       // }
                    }
                    
                }
                else if (wcscmp(Name, L"\\Device\\HarddiskVolume2\\Users\\Sergey\\Desktop\\config.csv") == 0)
                {
                    PUNICODE_STRING processName = NULL;
                    GetProcessImageName(PsGetCurrentProcess(), &processName);
                    if (wcscmp(processName->Buffer, L"\\Device\\HarddiskVolume2\\Users\\Sergey\\Desktop\\userapp.exe") != 0)
                    {
                        DbgPrint("Open CONFIG file %ws blocked for process %ws\n", Name, processName->Buffer);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        FltReleaseFileNameInformation(FileNameInfo);
                        return FLT_PREOP_COMPLETE;
                    }
                }
                
            }
        }
        FltReleaseFileNameInformation(FileNameInfo);
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
FsFilter1OperationStatusCallback (
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
                  ("FsFilter1!FsFilter1OperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FsFilter1!FsFilter1OperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

   // PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
              //    ("FsFilter1!FsFilter1PostOperation: Entered\n") );
    //DbgPrint("[Flt1]PostOperation: Entered\n");
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperationNoPostOperation (
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
                  ("FsFilter1!FsFilter1PreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FsFilter1DoRequestOperationStatus(
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
