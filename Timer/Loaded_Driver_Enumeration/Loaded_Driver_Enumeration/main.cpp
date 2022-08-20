#include <ntddk.h>

typedef unsigned char  BYTE;

KTIMER timer;
KDPC Dpc;


extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


#define SystemModuleInformation 11


VOID Unload(_In_ PDRIVER_OBJECT) {
    //cancel timer before unload
    auto status = KeCancelTimer(&timer);
    if (!status) {
        KdPrint(("faild to cancel Timer\n"));
    }
}

VOID
EnumerateLoadedDriverDPC(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);


PVOID list;
extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    list = DriverObject->DriverSection;
    DriverObject->DriverUnload = Unload;

    KeInitializeDpc(&Dpc, EnumerateLoadedDriverDPC, NULL);

    PVOID ZwQuerySystemInformation_FunctionIdentifire = MmLockPagableCodeSection(ZwQuerySystemInformation);
    if (!ZwQuerySystemInformation_FunctionIdentifire) {
        DbgPrint("Driver Enumeration: Failed to locks a section of Ntoskrn code 'ZwQuerySystemInformation'\n");
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeTimerEx(&timer, NotificationTimer);
    LARGE_INTEGER duetime = { 0 };
    duetime.QuadPart = -10000000;
    LONG period = 10000;
    KeSetTimerEx(&timer, duetime, period, &Dpc);


    return STATUS_SUCCESS;
}

VOID
EnumerateLoadedDriverDPC(
    PKDPC,
    PVOID,
    PVOID,
    PVOID
)
{
    ULONG BufferSize = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &BufferSize);

    RTL_PROCESS_MODULES* InformationData = (RTL_PROCESS_MODULES*)ExAllocatePool(NonPagedPool, BufferSize);
    if (!InformationData) {
        DbgPrint("Driver Failed Allocate memory\n ");
        return;
    }
    RtlZeroMemory(InformationData, BufferSize);

    Status = ZwQuerySystemInformation(SystemModuleInformation, InformationData, BufferSize, &BufferSize);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("Driver Failed  ZwQuerySystemInformation  %x\n", Status);
        return;
    }
    for (ULONG i = 0; i < InformationData->NumberOfModules; i++) {
        DbgPrint("Driver %s at Base Address %p \n", InformationData->Modules[i].FullPathName, InformationData->Modules[i].ImageBase);
    }

}
