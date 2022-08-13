#include <ntifs.h>
#include <ntddk.h>

// PROTOTYPES

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(NTAPI* PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

typedef
VOID
(NTAPI* PKKERNEL_ROUTINE)(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
	);

typedef
VOID
(NTAPI* PKRUNDOWN_ROUTINE) (
	_In_ PKAPC Apc
	);

extern "C"
VOID NTAPI KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PETHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
);


extern "C"
BOOLEAN NTAPI KeInsertQueueApc(_Inout_ PRKAPC Apc, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2, _In_ KPRIORITY Increment);


DRIVER_UNLOAD DriverUnload;
NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP Irp);

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);



VOID
NTAPI
ApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);


KSTART_ROUTINE  HookCPU;
void HookAllCPU();
void EnumerateKernelAPC(PETHREAD);
void EnumerateNormalAPC(PETHREAD thread);

volatile LONG ReleaseFlag = 1;
volatile LONG NumberOfCPUToHook = 0;
volatile LONG TotalCpuNumberHooked = 0;

PRKAPC KAPCKernel, KAPCUser;
DWORD64 LoadLibraryAddress = 0;


// DriverEntry
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {

	NTSTATUS Status = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\APCEnumeration");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create device (0x%08X)\n", status);
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\APCEnumeration");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	return Status;

}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\APCEnumeration");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP Irp) {

	auto stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;
	//ULONG DataWritten = 0;
	//ULONG IoctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	auto DataSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	auto UserData = (PVOID*)stack->Parameters.DeviceIoControl.Type3InputBuffer;


	__try {
		// check the user buffer, as the default methd is NEITHER
		ProbeForRead(UserData, DataSize, sizeof(UCHAR));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_ACCESS_VIOLATION;
		return  Status;
	}

	//copy the process Thread ID to local stack before rasing the IRQL to DISPATCH_LEVEL
	int counter = 0;

	DWORD64* ThreadID = (DWORD64*)UserData;
	DWORD64 ThreadIDArray[1000] = { 0 };
	while (ThreadID[counter]) {
		ThreadIDArray[counter] = ThreadID[counter];
		counter++;
	}
	ThreadIDArray[counter++] = 0;
	ThreadIDArray[counter] = 0;

	__try {
		//index 0 will be the address of LoadLibraryA will be used in user APC enumeration
		counter = 1;
		LoadLibraryAddress = ThreadIDArray[0];

		ReleaseFlag = 1;

		//Lock The Kernel To memory as i will run At IRQL=DISPATCH_LEVEL
		UNICODE_STRING	PsLookupThreadByThreadId_;
		PVOID	PsLookupThreadByThreadIdfn = NULL;
		RtlInitUnicodeString(&PsLookupThreadByThreadId_, L"PsLookupThreadByThreadId");
		PsLookupThreadByThreadIdfn = MmGetSystemRoutineAddress(&PsLookupThreadByThreadId_);

		PVOID PsLookupThreadByThreadId_FunctionIdentifire = MmLockPagableCodeSection(PsLookupThreadByThreadIdfn);
		if (!PsLookupThreadByThreadId_FunctionIdentifire) {
			DbgPrint(("APC Enumeration: Failed to locks a section of ntoskern.exe code\n"));
		}

		PVOID EnumerateKernelAPC_FunctionIdentifire = MmLockPagableCodeSection(EnumerateKernelAPC);
		if (!EnumerateKernelAPC_FunctionIdentifire) {
			DbgPrint(("APC Enumeration: Failed to locks a section of APCEnumeration code\n"));
		}

		PVOID EnumerateNormalAPC_FunctionIdentifire = MmLockPagableCodeSection(EnumerateNormalAPC);
		if (!EnumerateNormalAPC_FunctionIdentifire) {
			DbgPrint(("APC Enumeration: Failed to locks a section of APCEnumeration code\n"));
		}

		//Hook The other CPU except the current one, and raise IRQL on current processor to stop any APC dispatch
		//and so that no kernel apc gets executed while enumerating, the list will be accessed from two diffrent location and might lead to crash.
		HookAllCPU();


		//Raise IRQL to DISPATCH_LEVEL on current proccessor,
		KIRQL oldIrql = 0;
		if (DISPATCH_LEVEL >= KeGetCurrentIrql()) {
			KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
		}

		while (ThreadIDArray[counter] != 0) {

			DbgPrint("APC Enumeration for TID: %d\n", ThreadIDArray[counter]);
			PETHREAD Ethread;
			NTSTATUS status = PsLookupThreadByThreadId((HANDLE)ThreadIDArray[counter], &Ethread);
			if (NT_SUCCESS(status)) {
				DbgPrint("Start Enumerating Kernel APC\n");
				EnumerateKernelAPC(Ethread);

				DbgPrint("Start Enumerating User APC\n");
				EnumerateNormalAPC(Ethread);

				ObDereferenceObject(Ethread);
			}

			counter++;
		}

		//lower the IRQL on current processor
		KeLowerIrql(oldIrql);

		//Signal other threads on other processor to stop and release proseccor
		InterlockedDecrement(&ReleaseFlag);

		//loop until all other threads is stoped
		while (TotalCpuNumberHooked) {}

		DbgPrint(("Finished UnHooking other CPUs\n"));
		MmUnlockPagableImageSection(PsLookupThreadByThreadId_FunctionIdentifire);
		MmUnlockPagableImageSection(EnumerateKernelAPC_FunctionIdentifire);
		MmUnlockPagableImageSection(EnumerateNormalAPC_FunctionIdentifire);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
		DbgPrint("APC Enumeration: Error Access Violation while Enumerating APC Status Code 0x%x\n", Status);
		return Status;
	}


	return Status;
}


VOID HookAllCPU() {

	DbgPrint(("Attempting Hooking All CPUs Except the current processor\n"));
	DWORD64 nProcessor = KeNumberProcessors;
	NumberOfCPUToHook = (LONG)nProcessor - 1;
	int i = 0;
	HANDLE ThreadHandel = NULL;
	OBJECT_ATTRIBUTES inizializedattributes;
	InitializeObjectAttributes(&inizializedattributes, NULL, 0, NULL, NULL);
	for (i = 0; i < nProcessor - 1; i++) {
		DbgPrint("CPU %d is beining hooked\n", i);
		PsCreateSystemThread(&ThreadHandel, THREAD_ALL_ACCESS,
			NULL, NtCurrentProcess(), NULL,
			(PKSTART_ROUTINE)HookCPU, NULL);

		//Close The Handle
		ZwClose(ThreadHandel);
	}

	//loop untile the other CPU are Hooked
	while (NumberOfCPUToHook != TotalCpuNumberHooked) {}

	return;
}

VOID HookCPU(PVOID) {

	//Raise IRQL
	KIRQL oldIrql = 0;
	if (DISPATCH_LEVEL >= KeGetCurrentIrql()) {
		KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
	}
	//NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

	InterlockedIncrement(&TotalCpuNumberHooked);

	//Loop Untile Released
	while (ReleaseFlag) {}

	//DbgPrint(("The CPU is Released\n"));

	//Lower IRQL
	KeLowerIrql(oldIrql);

	InterlockedDecrement(&TotalCpuNumberHooked);
	//terminate itself
	PsTerminateSystemThread(STATUS_SUCCESS);
}


void EnumerateKernelAPC(PETHREAD thread) {

	KAPCKernel = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'APC');
	if (!KAPCKernel) {
		DbgPrint(("APC Enumeration: Failed to Allocate Memory for the APC structure\n"));
		return;
	}


	KeInitializeApc(KAPCKernel, thread, OriginalApcEnvironment, ApcKernelRoutine,
		NULL, NULL, KernelMode, 0);


	BOOLEAN ret = FALSE;
	ret = KeInsertQueueApc(KAPCKernel, NULL, NULL, 0);
	if (ret == FALSE) {
		DbgPrint(("APC Enumeration: Failed to insert the APC\n"));
		return;
	}

	int Cou = 0;
	PLIST_ENTRY temp = 0;
	temp = (LIST_ENTRY*)KAPCKernel->ApcListEntry.Flink;
	PLIST_ENTRY MyListHead = (LIST_ENTRY*)&KAPCKernel->ApcListEntry;
	while (MyListHead != temp && temp != temp->Flink) {

		PKAPC info = CONTAINING_RECORD(temp, KAPC, ApcListEntry);
		DbgPrint("KernelRoutine: 0x%p  RundownRoutine: 0x%p  NormalRoutine: 0x%p\n", info->Reserved[0], info->Reserved[1], info->Reserved[2]);
		Cou++;
		temp = temp->Flink;

	}
	PKAPC info = CONTAINING_RECORD(temp, KAPC, ApcListEntry);
	DbgPrint("KernelRoutine: 0x%p  RundownRoutine: 0x%p  NormalRoutine: 0x%p\n", info->Reserved[0], info->Reserved[1], info->Reserved[2]);

}

void EnumerateNormalAPC(PETHREAD thread) {

	KAPCUser = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'APC');
	if (!KAPCUser) {
		DbgPrint(("APC Enumeration: Failed to Allocate Memory for the APC structure\n"));
		return;
	}


	KeInitializeApc(KAPCUser, thread, OriginalApcEnvironment, ApcKernelRoutine,
		NULL, (PKNORMAL_ROUTINE)LoadLibraryAddress, UserMode, 0);	//0x0000000055555555


	BOOLEAN ret = FALSE;
	ret = KeInsertQueueApc(KAPCUser, NULL, NULL, 0);
	if (ret == FALSE) {
		DbgPrint(("APC Enumeration: Failed to insert the APC\n"));
		return;
	}

	int Cou = 0;
	PLIST_ENTRY temp = 0;
	temp = (LIST_ENTRY*)KAPCUser->ApcListEntry.Flink;
	PLIST_ENTRY MyListHead = (LIST_ENTRY*)&KAPCUser->ApcListEntry;
	while (MyListHead != temp && temp != temp->Flink) {

		PKAPC info = CONTAINING_RECORD(temp, KAPC, ApcListEntry);
		DbgPrint("KernelRoutine: 0x%p  RundownRoutine: 0x%p  NormalRoutine: 0x%p\n", info->Reserved[0], info->Reserved[1], info->Reserved[2]);

		Cou++;
		temp = temp->Flink;

	}
	PKAPC info = CONTAINING_RECORD(temp, KAPC, ApcListEntry);
	DbgPrint("KernelRoutine: 0x%p  RundownRoutine: 0x%p  NormalRoutine: 0x%p\n", info->Reserved[0], info->Reserved[1], info->Reserved[2]);

}

VOID
NTAPI
ApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
) {
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(Apc);
}
