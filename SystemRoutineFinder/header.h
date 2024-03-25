#pragma once
#pragma once
#include<minwindef.h>
#include<aux_klib.h>
#pragma comment(lib,"aux_klib.lib")
#include<ntimage.h>
#ifdef _NTIFS_
namespace kernel {
#define Print(ComponentId, Level, _Format, ...) \
{DbgPrintEx(ComponentId, Level, _Format".\r\n",  __VA_ARGS__);}
#define PrintEx(ComponentId, Level, _Format, ...) \
{KdPrintEx((ComponentId, Level, _Format".\r\n", __VA_ARGS__));}
	EXTERN_C PVOID RtlImageDirectoryEntryToData(IN PVOID Base,
		IN BOOLEAN MappedAsImage,
		IN USHORT DirectoryEntry,
		OUT PULONG Size);
#define TAG 12584
	inline PVOID MiFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName)
		/*
		写作目的：
		MmGetSystemRoutineAddress这个函数有如下的限制：
		It can only be used for routines exported by the kernel or HAL, not for any driver-defined routine.
		FltGetRoutineAddress这个函数有如下的限制：
		1.调用的函数。
		2.那个模块必须已经加载。
		NdisGetRoutineAddress有类似的限制。
		有时候获取别的内核模块的函数的地址是一个解决问题的办法，如：WINHV.sys。
		有人为此还专门写了函数，当然是解析PE32/PE32+了。
		其实系统已经提供了一些函数，只不过导出而没有公开而已。
		看WRK知道:MmGetSystemRoutineAddress是通过MiFindExportedRoutineByName实现的。
		可是：MiFindExportedRoutineByName没有导出，定位又没有好的稳定的办法。
		所以自己实现，还好RtlImageDirectoryEntryToData（RtlImageNtHeader）已经导出。
		注意：
		如果是获取应用层的地址，需要附加到进程。

		*/
	{
		USHORT OrdinalNumber;
		PULONG NameTableBase;
		PUSHORT NameOrdinalTableBase;
		PULONG Addr;
		LONG High;
		LONG Low;
		LONG Middle;
		LONG Result;
		ULONG ExportSize;
		PVOID FunctionAddress = 0;
		PIMAGE_EXPORT_DIRECTORY ExportDirectory;
		PAGED_CODE();
		__try {
			FunctionAddress = *(PVOID*)DllBase;
			FunctionAddress = 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FunctionAddress;
		}
		//确保DllBase可以访问。否则蓝屏。
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			&ExportSize);
		if (ExportDirectory == NULL) {
			return NULL;
		}
		// Initialize the pointer to the array of RVA-based ansi export strings. 
		NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);
		// Initialize the pointer to the array of USHORT ordinal numbers. 
		NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
		Low = 0;
		Middle = 0;
		High = ExportDirectory->NumberOfNames - 1;
		while (High >= Low) // Lookup the desired name in the name table using a binary search.
		{
			// Compute the next probe index and compare the import name with the export name entry.
			Middle = (Low + High) >> 1;
			Result = strcmp(AnsiImageRoutineName->Buffer, (PCHAR)DllBase + NameTableBase[Middle]);
			if (Result < 0) {
				High = Middle - 1;
			}
			else if (Result > 0) {
				Low = Middle + 1;
			}
			else {
				break;
			}
		}
		// If the high index is less than the low index, then a matching table entry was not found.
		// Otherwise, get the ordinal number from the ordinal table.
		if (High < Low) {
			return NULL;
		}
		OrdinalNumber = NameOrdinalTableBase[Middle];
		// If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
		// Return not found.
		if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
			return NULL;
		}
		// Index into the array of RVA export addresses by ordinal number.
		Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
		FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

		// Forwarders are not used by the kernel and HAL to each other.
		ASSERT((FunctionAddress <= (PVOID)ExportDirectory) ||
			(FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

		return FunctionAddress;
	}
#define MAXPATHLEN     1024
	inline NTSTATUS GetObjectNtName(_In_ PVOID Object, _Inout_ PUNICODE_STRING NtName)
	{
		ULONG length = MAXPATHLEN;
		PUNICODE_STRING Temp;
		NTSTATUS Status = STATUS_SUCCESS;
		UNICODE_STRING  KeyPath = { 0 };
		if (NULL == Object) {
			Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%p", Object);
			return STATUS_UNSUCCESSFUL;
		}
		Temp = (PUNICODE_STRING)ExAllocatePool2(PagedPool, length, TAG);//函数内释放。
		if (Temp == 0) {
			Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "bad alloc");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		Status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)Temp, length, &length);
		if (!NT_SUCCESS(Status)) {
			//Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//这个也不少。
			ExFreePoolWithTag(Temp, TAG);
			return Status;
		}
		RtlInitUnicodeString(&KeyPath, Temp->Buffer);

		NtName->MaximumLength = KeyPath.MaximumLength + sizeof(wchar_t);
		NtName->Buffer = (PWCH)ExAllocatePool2(PagedPool, NtName->MaximumLength, TAG);//WorkItem完成后释放。
		if (0 == NtName->Buffer) {
			Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "bad alloc");
			ExFreePoolWithTag(Temp, TAG);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(NtName->Buffer, NtName->MaximumLength);
		RtlCopyUnicodeString(NtName, &KeyPath);
		ExFreePoolWithTag(Temp, TAG);
		return Status;
	}
	inline void GetSystemRootPathName(PUNICODE_STRING PathName,
		PUNICODE_STRING NtPathName,
		PUNICODE_STRING DosPathName
	)
		/*
		功能：主要是获取L"\\SystemRoot"的NT和DOS路径，但是也可以获取以L"\\SystemRoot"开头的任何合法且存在的路径。

		例如：你可直接获取下面文件的（NT和DOS的）路径，而无需硬编码了。
		1.L"\\SystemRoot"
		2.L"\\SystemRoot\\System32\\ntdll.dll"
		3.L"\\SystemRoot\\System32\\smss.exe"
		4.L"\\SystemRoot\\System32\\csrss.exe"
		5.等等。
		*/
	{
		HANDLE File;
		NTSTATUS st;
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
		IO_STATUS_BLOCK IoStatus;
		PFILE_OBJECT FileObject = { 0 };
		UNICODE_STRING FullName = { 0 };
		POBJECT_NAME_INFORMATION FileNameInfo = NULL;
		InitializeObjectAttributes(&ObjectAttributes, PathName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		st = ZwOpenFile(&File, SYNCHRONIZE | FILE_READ_DATA, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, 0);
		ASSERT(NT_SUCCESS(st));
		st = ObReferenceObjectByHandle(File, FILE_READ_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, 0);
		ASSERT(NT_SUCCESS(st));
		st = GetObjectNtName(FileObject, &FullName);
		ASSERT(NT_SUCCESS(st));
		if (NULL == FullName.Buffer) {
			Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "bad alloc");
		}else {
			RtlCopyUnicodeString(NtPathName, &FullName);
			st = IoQueryFileDosDeviceName(FileObject, &FileNameInfo);
			ASSERT(NT_SUCCESS(st));
			RtlCopyUnicodeString(DosPathName, &FileNameInfo->Name);
			ExFreePool(FileNameInfo);
			ExFreePoolWithTag(FullName.Buffer, TAG);
		}
		ObDereferenceObject(FileObject);
		ZwClose(File);
	}
	inline ULONG Rva2Offset(IN LPVOID Data, IN ULONG Rva){
		ULONG Offset = 0;//返回值。
		IMAGE_FILE_HEADER* FileHeader = NULL;
		IMAGE_SECTION_HEADER* SectionHeader = NULL;
		USHORT i = 0;
		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)Data;
		if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
			return 0;
		}
		FileHeader = (IMAGE_FILE_HEADER*)((SIZE_T)DosHeader->e_lfanew + sizeof(ULONG) + (SIZE_T)Data);
		SectionHeader = (IMAGE_SECTION_HEADER*)((ULONG)(ULONG)DosHeader->e_lfanew +
			sizeof(ULONG) +
			sizeof(IMAGE_FILE_HEADER) +
			FileHeader->SizeOfOptionalHeader);//必须加(ULONG),不然出错.
		SectionHeader = (IMAGE_SECTION_HEADER*)((SIZE_T)SectionHeader + (SIZE_T)Data);
		for (; i < FileHeader->NumberOfSections; i++) //规范规定是从1开始的.
		{
			if (Rva >= SectionHeader[i].VirtualAddress && Rva <=
				(SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize)) {
				Offset = Rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
				break;
			}
		}
		return Offset;
	}
	inline PVOID MiFindExportedRoutineByNameEx(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName)
		/*++
		Routine Description:
			This function searches the argument module looking for the requested exported function name.
		Arguments:
			DllBase - Supplies the base address of the requested module.
			AnsiImageRoutineName - Supplies the ANSI routine name being searched for.
		Return Value:
			The virtual address of the requested routine or NULL if not found.
		--*/
		/*
		此函数适用于获取只映射(map)而没有加载(load)的有导出函数的PE文件的函数地址的获取。
		*/
	{
		USHORT OrdinalNumber;
		PULONG NameTableBase;
		PUSHORT NameOrdinalTableBase;
		PULONG Addr;
		LONG High;
		LONG Low;
		LONG Middle;
		LONG Result;
		ULONG ExportSize;
		PVOID FunctionAddress = 0;
		PIMAGE_EXPORT_DIRECTORY ExportDirectory;
		ULONG Rva;
		ULONG Offset;
		PAGED_CODE();
		__try {
			FunctionAddress = *(PVOID*)DllBase;
			FunctionAddress = 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FunctionAddress;
		}
		//确保DllBase可以访问。否则蓝屏。
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			&ExportSize);
		if (ExportDirectory == NULL) {
			return NULL;
		}
		Rva = (ULONG)((SIZE_T)ExportDirectory - (SIZE_T)DllBase);
		Offset = Rva2Offset(DllBase, Rva);
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((SIZE_T)DllBase + Offset);
		Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfNames);
		NameTableBase = (PULONG)((SIZE_T)DllBase + Offset);
		Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfNameOrdinals);
		NameOrdinalTableBase = (PUSHORT)((SIZE_T)DllBase + Offset);
		Low = 0;
		Middle = 0;
		High = ExportDirectory->NumberOfNames - 1;
		while (High >= Low) // Lookup the desired name in the name table using a binary search.
		{
			SIZE_T temp = 0;
			PCHAR p = NULL;
			Middle = (Low + High) >> 1;// Compute the next probe index and compare the import name with the export name entry.
			Offset = Rva2Offset(DllBase, NameTableBase[Middle]);
			temp = (SIZE_T)((SIZE_T)DllBase + Offset);
			p = (PCHAR)temp;
			Result = strcmp(AnsiImageRoutineName->Buffer, p);
			if (Result < 0) {
				High = Middle - 1;
			}
			else if (Result > 0) {
				Low = Middle + 1;
			}
			else {
				break;
			}
		}
		// If the high index is less than the low index, then a matching table entry was not found.
		// Otherwise, get the ordinal number from the ordinal table.
		if (High < Low) {
			return NULL;
		}
		OrdinalNumber = NameOrdinalTableBase[Middle];// + ExportDirectory->Base

		// If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
		// Return not found.
		if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
			return NULL;
		}
		// Index into the array of RVA export addresses by ordinal number.
		Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfFunctions);
		Addr = (PULONG)((PCHAR)DllBase + Offset);
		Offset = Rva2Offset(DllBase, Addr[OrdinalNumber]);
		FunctionAddress = (PVOID)((PCHAR)DllBase + Offset);
		// Forwarders are not used by the kernel and HAL to each other.
		ASSERT((FunctionAddress <= (PVOID)ExportDirectory) ||
			(FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));
		return FunctionAddress;
	}
	inline int GetIndexByName(PANSI_STRING NtRoutineName) {
		HANDLE ImageFileHandle;
		IO_STATUS_BLOCK IoStatus;
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
		HANDLE Section;
		PVOID ViewBase;
		SIZE_T ViewSize;
		KAPC_STATE ApcState;
		NTSTATUS Status;
		HANDLE  Handle = 0;
		int index = -1;
		//////////////////////////////////////////////////////////////////////////////////////////////
		UNICODE_STRING NTDLL = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
		wchar_t NtNTDLL[MAX_PATH] = { 0 };
		UNICODE_STRING g_NtNTDLL = { 0 };
		wchar_t DosNTDLL[MAX_PATH] = { 0 };
		UNICODE_STRING g_DosNTDLL = { 0 };
		RtlInitUnicodeString(&g_NtNTDLL, NtNTDLL);
		g_NtNTDLL.MaximumLength = sizeof(NtNTDLL);
		RtlInitUnicodeString(&g_DosNTDLL, DosNTDLL);
		g_DosNTDLL.MaximumLength = sizeof(DosNTDLL);

		GetSystemRootPathName(&NTDLL, &g_NtNTDLL, &g_DosNTDLL);
		//////////////////////////////////////////////////////////////////////////////////////////////
		// Attempt to open the driver image itself.
		// If this fails, then the driver image cannot be located, so nothing else matters.
		InitializeObjectAttributes(&ObjectAttributes,
			&NTDLL,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		Status = ZwOpenFile(&ImageFileHandle,
			FILE_READ_DATA,// FILE_EXECUTE
			&ObjectAttributes,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_DELETE,
			0);
		if (!NT_SUCCESS(Status)) {
			return index;
		}
		InitializeObjectAttributes(&ObjectAttributes,
			NULL,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		Status = ZwCreateSection(&Section,
			SECTION_MAP_READ,// SECTION_MAP_EXECUTE
			&ObjectAttributes,
			NULL,
			PAGE_READONLY,// PAGE_EXECUTE
			SEC_COMMIT,
			ImageFileHandle);
		if (!NT_SUCCESS(Status)) {
			ZwClose(ImageFileHandle);
			return index;
		}
		ViewBase = NULL;
		ViewSize = 0;
		// Since callees are not always in the context of the system process, 
		// attach here when necessary to guarantee the driver load occurs in a known safe address space to prevent security holes.
		KeStackAttachProcess(PsInitialSystemProcess, &ApcState);
		Status = ObOpenObjectByPointer(PsInitialSystemProcess,
			OBJ_KERNEL_HANDLE,
			NULL,
			GENERIC_READ,
			*PsProcessType,
			KernelMode,
			&Handle);
		ASSERT(NT_SUCCESS(Status));
		Status = ZwMapViewOfSection(Section, Handle, &ViewBase, 0L, 0L, NULL, &ViewSize, ViewShare, 0L, PAGE_READONLY);//PAGE_EXECUTE
		if (!NT_SUCCESS(Status)) {
			ZwClose(Handle);
			KeUnstackDetachProcess(&ApcState);
			ZwClose(Section);
			ZwClose(ImageFileHandle);
			return index;
		}
		__try {
			PVOID FunctionAddress = MiFindExportedRoutineByNameEx(ViewBase, NtRoutineName);
			ASSERT(FunctionAddress);

#ifdef _WIN64
			index = (*(PULONG)((PUCHAR)FunctionAddress + 4));
#else
			index = (*(PULONG)((PUCHAR)FunctionAddress + 1));
#endif 
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
		}
		ZwUnmapViewOfSection(Handle, ViewBase);
		KeUnstackDetachProcess(&ApcState);
		ZwClose(Section);
		ZwClose(ImageFileHandle);
		ZwClose(Handle);
		return index;
	}
	inline PVOID GetNtBase()
		/*
		功能：获取NT内核的基地址。

		其实有一个更简单的办法，只有知道NT里的一个地址，然后调用一个函数即可获得，这个API便是RtlPcToFileHeader。

		运行环境，说是NTDDI_VISTA，其实2003都有了，但是有的WDK里不包含相应的lib（Aux_klib.lib）。
		*/
	{
		NTSTATUS Status = 0;
		ULONG  modulesSize = 0;
		PAUX_MODULE_EXTENDED_INFO modules;
		ULONG  numberOfModules;
		ULONG i;
		PVOID ImageBase = 0;
		Status = AuxKlibInitialize();
		if (!NT_SUCCESS(Status)) {
			PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
			return ImageBase;
		}
		// Get the required array size.
		Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
		if (!NT_SUCCESS(Status) || modulesSize == 0) {
			PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
			return ImageBase;
		}
		// Calculate the number of modules.
		numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
		// Allocate memory to receive data.
		modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(PagedPool, modulesSize, TAG);
		if (modules == NULL) {
			Status = STATUS_INSUFFICIENT_RESOURCES;
			PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
			return ImageBase;
		}
		RtlZeroMemory(modules, modulesSize);
		// Obtain the module information.
		Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
		if (!NT_SUCCESS(Status)) {
			PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
			ExFreePoolWithTag(modules, TAG);
			return ImageBase;
		}
		for (i = 0; i < numberOfModules; i++) {
			//UCHAR * FileName = modules[i].FullPathName + modules[i].FileNameOffset;

			if (i == 0) {
				ImageBase = modules[i].BasicInfo.ImageBase;
				break;
			}
		}
		ExFreePoolWithTag(modules, TAG);
		return ImageBase;
	}
	inline SIZE_T GetZwRoutineAddressByName(PANSI_STRING ZwRoutineName)
		/*
		功能：获取X64上没有导出的Zw函数。
		注释：1.凡有Nt的函数都有对应的Zw函数。
			  2.在开启驱动程序验证器的情况下ZwCreateFile的值是nt!VfZwCreateFile。
			  3.在开启驱动程序验证器的情况下用MmGetSystemRoutineAddress获取的ZwCreateFile的值也是nt!VfZwCreateFile。
			  4.无论ZwCreateFile处的内容变成啥，但是那个地址还是它的地址，这个是不变的。
			  5.MiFindExportedRoutineByName获取的才是真正的ZwCreateFile地址。
		*/
	{
		SIZE_T p = 0;
		SIZE_T CreateFile = (SIZE_T)ZwCreateFile;
		SIZE_T CreateKey = (SIZE_T)ZwCreateKey;
		ANSI_STRING File = RTL_CONSTANT_STRING("ZwCreateFile");
		ANSI_STRING Key = RTL_CONSTANT_STRING("ZwCreateKey");
		int ZwCreateFileIndex = GetIndexByName(&File);
		int ZwCreateKeyIndex = GetIndexByName(&Key);
		int x = 0;
		SIZE_T y = 0;
		SIZE_T z = 0;
		SIZE_T base;
		int index = 0;
		LONG_PTR t = 0;
		if (-1 == ZwCreateFileIndex || -1 == ZwCreateKeyIndex) {
			return 0;
		}
		CreateFile = (SIZE_T)MiFindExportedRoutineByName(GetNtBase(), &File);
		CreateKey = (SIZE_T)MiFindExportedRoutineByName(GetNtBase(), &Key);
		if ((ZwCreateFileIndex - ZwCreateKeyIndex) > 0) {
			x = ZwCreateFileIndex - ZwCreateKeyIndex;
		}
		else {
			x = ZwCreateKeyIndex - ZwCreateFileIndex;
		}
		t = CreateFile - CreateKey;
		if (t > 0) {
			y = CreateFile - CreateKey;
		}
		else {
			y = CreateKey - CreateFile;
		}
		z = y / x;
		base = CreateFile - ZwCreateFileIndex * z;
		ASSERT(base == CreateKey - ZwCreateKeyIndex * z);
		/*
		因为有的ZW函数没有在内核导出，所以这里要访问NTDLL.DLL。
		*/
		index = GetIndexByName(ZwRoutineName);
		p = base + index * z;
		return p;
	}
	inline SIZE_T GetZwRoutineAddress(PCSTR RoutineName)
		/*
		功能：获取内核中的Zw系列函数的地址（主要是没有导出的），支持X86和AMD64。

		注意事项：
		1.建议在驱动入口的上下文中执行。
		2.仅仅是示例。里面的初始化函数用到了全局变量，这时为了省事。
		3.此函数有待改进，如：完美和简单是矛盾的，不能同时满足。
		*/
	{
		SIZE_T RoutineAddress = 0;
		ANSI_STRING ZwRoutineName = { 0 };
		RtlInitAnsiString(&ZwRoutineName, RoutineName);
		RoutineAddress = GetZwRoutineAddressByName(&ZwRoutineName);
		return RoutineAddress;
	}
}
#else
#error kernel mode only
#endif


