#include "global.h"

#define NTDLL_MAX_SIZE 0x400000		///Never has an ntdll been observed exceeding 1.8 MB in size. We have a good safety margin.
#define NTDLL_MIN_SIZE 0x80000		///Never has a 64 bit ntdll been observed being smaller than 500 KB.

///It is not likely that a handle value ever happens to be larger than MAXULONG:
///On Windows there exists a per-process handle limit of 16MiB handles and since as soon as new handles are opened they
///first will fill the empty handle table entries of previously closed handles before higher handle number are created,
///the theoretical maximum value can't exceed 16MiB*4=0x4000000. In case of design changes we define the max value 4 times as big.
#define MAX_HANDLE_VALUE_LIKELY MAXULONG	
#define NT_SYSCALL_START 0x0	///System call numbers always started with 0.
#define NT_SYSCALL_END 0x1000	///0x1000 is the begin of win32k system calls and hence, the last possible NT syscall is 0xFFF.
#define NT_INVALID_SYSCALL 0xFFF	///Since 0xFFF is very unlikely though we define if as an invalid system call.

///By preallocating a buffer we avoid having to perform a large (and hence suspicious) NtAllocateVirtualMemory allocation.
///Note, that NtAllocateVirtualMemory can be hooked.
static UCHAR sg_pRawNtdll[NTDLL_MAX_SIZE];		
static char sg_pSyscallTable[NTDLL_MAX_SIZE/2];

///We define a generic system call structure which helds true ever since Windows NT 3.51.
typedef struct _NT_SYSCALL_STUB {
	BYTE movR64Rcx[3];
	BYTE movR32Imm32;
	ULONG syscallNumber;
	USHORT intelSyscallInstruction;
	BYTE ret;
	BYTE nopPadding[5];
} NT_SYSCALL_STUB, *PNT_SYSCALL_STUB;

void dispError(NTSTATUS status) {
	ULONGLONG dummy;
	for (ULONG i = NT_SYSCALL_START; i < NT_SYSCALL_END; i++) {
		dummy = 0;
		syscallStub(i, status, 1, 0, (PULONG_PTR)&dummy, 0, (PULONG)&dummy);
	}
}

///This is our core initialization routine. Here we will bruteforce crucial syscall numbers to finally read a pristine
///on-disk ntdll into loader-allocated memory "sg_pNtdll". In particular, this are the numbers for:
///==> NtClose
///==> NtOpenFile
///==> NtQueryInformationFile
///==> NtReadFile
NTSTATUS performCoreInitialization(PVOID pNtdllBuffer, ULONGLONG ntdllBufferSize, PULONG pDebugBuffer, PULONG pFirstOccurenceApi) {
	UNICODE_STRING uNtdll;
	OBJECT_ATTRIBUTES fileAttr;
	IO_STATUS_BLOCK ioSb;
	CONTEXT dummyCtx;
	FILE_STANDARD_INFORMATION ntdllInfo;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hArbObject = NULL;
	ULONG syscallnumNtClose = NT_INVALID_SYSCALL;
	ULONG syscallnumNtOpenFile = NT_INVALID_SYSCALL;
	ULONG syscallnumNtQueryInformationFile = NT_INVALID_SYSCALL;
	HANDLE hTestHandle = INVALID_HANDLE_VALUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WCHAR szFullNtdllName[] = L"\\systemroot\\system32\\ntdll.dll";
	ULONGLONG ntdllSize = 0;

	if (!pNtdllBuffer || !pDebugBuffer || !pFirstOccurenceApi || (ntdllBufferSize > NTDLL_MAX_SIZE))
		return STATUS_INVALID_PARAMETER;

	*pDebugBuffer = 0;
	*pFirstOccurenceApi = 0;

	///We will first try to find the NtClose syscall to prevent it from interfering with our other bruteforce attempts.
	///E.g. If we were to find NtOpenFile and then tried to find NtReadFile but the NtClose call happened
	///to appear before NtReadFile we would inadvertently close our handle and therefore use an invalid handle
	///while attempting to find still unknown NtReadFile number and to read the file.
	///We will exploit the fact that every process gets a few handles duplicated or inherited before even the
	///very first instruction in the processes image. This might also be related to the usermode loader behavior.
	///Since all these handles should be closable we just pick one after another and try to close them.
	///A successful NtClose is defined as an operation which once succeeds using syscall number "n" and then fails
	///with msdn-defined 0xC0000008 using both the very same syscall number and the same handle value.
	for (ULONGLONG i = 4; i < 0x100; i++) {
		hArbObject = (HANDLE)i;
		for (ULONG candNtClose = NT_SYSCALL_START; candNtClose < NT_SYSCALL_END; candNtClose++) {
			///Try to call NtClose on the handle the first time.
			///Notice the bad aligned 64 bit values. These are to prevent NtWaitForXxx calls from working since not only
			///does NtWaitForSingleObject have similar parameters but it also waits on a handle if the other parameters
			///are specified with NULL/0. Clearly, our thread would be "stopped" if we ran into an NtWaitForXxx call
			///while searching for NtClose. With the bad pointers it returns 0xC0000005 or 0x80000002 and does not wait. :) 
			status = syscallStub(candNtClose, hArbObject, 0x1111111111111111, 0x3333333333333333, 0x7777777777777777);
			if (STATUS_HANDLE_NOT_CLOSABLE == status) {	///We have found NtClose for sure but NtOpenFile provided us with a 
				syscallnumNtClose = candNtClose;		///wrong (yet valid) handle value. We break the loop and note the NtClose
				i = 0x100;								///number so the next time we don't have to scan for it again.
				break;
			}

			if (status)
				continue;

			///Did it succeed? Then call it the second time with the very same syscall number.
			status = syscallStub(candNtClose, hArbObject, 0x1111111111111111, 0x3333333333333333, 0x7777777777777777);
			if (STATUS_INVALID_HANDLE != status)	///If we now don't receive C0000008 (refer to msdn) we have not yet closed the handle
				continue;							///and consequently not found NtClose. We'll try on.

			syscallnumNtClose = candNtClose;
			i = 0x100;
			break;
		}
	}

	///If we could not find NtClose we can't continue.
	if (NT_INVALID_SYSCALL == syscallnumNtClose) {
		*pDebugBuffer = 1;
		return STATUS_ORDINAL_NOT_FOUND;
	}

	hTestHandle = (HANDLE)0xDBBDBBDBBDBDBCD1; ///This value is not divisibly by 4 without remainder. 
	for (ULONG candNtOpenFile = NT_SYSCALL_START; candNtOpenFile < NT_SYSCALL_END; candNtOpenFile++) {
		if (syscallnumNtClose == candNtOpenFile)
			continue;

		///If we start over the next iteration we just renew EVERYTHING. Since we can't expect the completely
		///wrong called and failing routines to not alter our various pointer targets we need to be as paranoid
		///as even possible and hence to everytime restart from scratch even if it costs more CPU time.
		ioSb.Status = 0xBADBAAAD;
		uNtdll.Buffer = szFullNtdllName;
		uNtdll.LengthInBytes = sizeof(szFullNtdllName) - 2;
		uNtdll.MaximumLengthInBytes = sizeof(szFullNtdllName);
		InitializeObjectAttributes(&fileAttr, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
		RtlSecureZeroMemory(&dummyCtx, sizeof(CONTEXT));

		///Tests have shown that there is an NtContinue call which tries to execute invalid code in the own process when given
		///simply a correct ContextFlags value of CONTEXT_AMD64 | 0x00000001. If we call NtOpenFile(&hFile) where hFile is
		///located on the stack (by default) but in fact call NtContinue (since we don't know the syscall number yet!)
		///the stack just needs to look like a CONTEXT structure with those ContextFlags set to any value which in case
		///of an NtContinue call would include setting the RIP register. And we don't have too much knowledge and control of what
		///happens to be on our stack especially, when calling completely random routines which can change the stack in various ways...
		///For that reason we somewhat "define" what is located on our stack by allocating a real CONTEXT structure ourselves
		///and initializing it with CONTEXT_AMD64 ContextFlags which does not set Rip register. That way, we can avoid
		///"unauthorized" code execution.
		///Luckily, the CONTEXT structure's first member is not ContextFlags but an unused value so we can easily initialize the
		///first member with a bogus handle value and then let NtCreateFile deem it as an PHANDLE.
		dummyCtx.ContextFlags = CONTEXT_AMD64;
		dummyCtx.P1Home = (ULONGLONG)hTestHandle;
		status = syscallStub(candNtOpenFile, &dummyCtx, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
		hFile = (HANDLE)dummyCtx.P1Home;

		///These are NTSTATUS values which are not likely with any other call than NtOpenFile or NtCreateFile.
		///given the object path of \systemroot\system32 which cannot be e.g. a registry key... If we get one of these
		///values we set a debug value so we know easier that we have a file problem in case of an error.
		if (STATUS_OBJECT_NAME_INVALID == status ||
			STATUS_OBJECT_NAME_NOT_FOUND == status ||
			STATUS_OBJECT_PATH_INVALID == status ||
			STATUS_OBJECT_PATH_NOT_FOUND == status ||
			STATUS_OBJECT_PATH_SYNTAX_BAD == status) {
			if (!*pFirstOccurenceApi) {
				///Safe for later that we're likely to have a problem with our file name.
				*pFirstOccurenceApi = candNtOpenFile;
			}
		}

		///This test has an extremely strong filtering behavior! Not only has the syscall recognized our buffer
		///which is not the first or second parameter (like in NtGetXxx apis) but it has also written something in there.
		///Only a few syscalls pass this test.
		if (0xBADBAAAD == ioSb.Status)
			continue;

		if (status)		///Obviously, we expect nothing than STATUS_SUCCESS and since we attempted to open the file synchronously
			continue;	///There cannot be returned a STATUS_PENDING.

						///At this point, we successfully returned from the system call.
						///First let us conduct some handle value analysis:
						///We know that a valid file handle value must be evenly divisible by 4 and it must be greater than 0.
						///This also implies that the handle value must have been changed (since above fake value is not divisible by 4!),
						///so we can detect fake STATUS_SUCCESS returned by NtYieldExecution and continue the loop.
						///It further implies, that the returned handle value cannot be magic number "INVALID_HANDLE_VALUE"
						///as this isn't divisible by 4, either.
						///First tests have shown that there do exist APIs which zero out only the least significant ULONG.
						///As this would lead to a test pass since the handle is then not NULL yet ends with a nibble value
						///divisible by 4 we simply introduce another check whether the handle value is unlikely large.
						///Please refer to the #define in order to understand the decision of the maximum value.
		if (!hFile || ((ULONGLONG)hFile % 4) || (MAX_HANDLE_VALUE_LIKELY < (ULONGLONG)hFile))
			continue;
		
		*pDebugBuffer = 3;
		///We now attempt to query the file size. If it is smaller or larger than NTDLL_MAX_SIZE/NTDLL_MIN_SIZE
		///We have possibly not opened the correct file or queried information using a wrong handle.
		///We will bail out and try with the next NtOpenFile syscallNumber.
		for (ULONG candNtQueryInformationFile = NT_SYSCALL_START; candNtQueryInformationFile < NT_SYSCALL_END; candNtQueryInformationFile++) {
			if ((syscallnumNtClose == candNtQueryInformationFile))
				continue;	///Skip the ones we already know...

			ioSb.Status = 0x13371337;
			RtlSecureZeroMemory(&ntdllInfo, sizeof(FILE_STANDARD_INFORMATION));

			status = syscallStub(candNtQueryInformationFile, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
			if (0x13371337 == ioSb.Status)	///This test has an extremely strong filtering behavior!
				continue;

			if (status)
				continue;

			if ((NTDLL_MIN_SIZE < ntdllInfo.EndOfFile.QuadPart) &&
				(ntdllInfo.EndOfFile.QuadPart <= ntdllInfo.AllocationSize.QuadPart) &&
				(ntdllInfo.AllocationSize.QuadPart <= NTDLL_MAX_SIZE)) {
				*pDebugBuffer = 4;
				///The retrieved ntdll.dll size is reasonable, we are likely to have figured
				///out the NtOpenFile system call correctly.
				ntdllSize = ntdllInfo.EndOfFile.QuadPart;
				if (ntdllBufferSize < ntdllSize)
					return STATUS_BUFFER_TOO_SMALL;

				syscallnumNtOpenFile = candNtOpenFile;
				syscallnumNtQueryInformationFile = candNtQueryInformationFile;
				break;
			}
		}

		if (ntdllSize)		///If ntdllSize is set it means that we are likely to have found and opened a valid ntdll file.
			break;			///Otherwise we will continue the outer loop, since maybe we received a fake handle of wrong NtOpenFile.
	}

	if (NT_INVALID_SYSCALL == syscallnumNtOpenFile) {	///This means we could not even open the file. Maybe AV/HIPS
		*pDebugBuffer = 5;								///prevents even read access to the ntdll.dll DLL?
		return STATUS_ORDINAL_NOT_FOUND;			
	}

	///If we made it till here we strongly assume that we have found not only the correct NtOpenFile but also the correct
	///NtClose and NtQueryInformationFile number. We now have pretty good chances of succeeding upon attemping to read the
	///ntdll.dll file into memory. If we don't succeed in reading the file before certain syscall
	///(on Windows 10, Build 10240 it is the 0x1B3 syscall number) our program will get stuck in new
	///NtWaitForAlertByThreadId call. This is due to 2nd parameter of NtReadFile which must be NULL or a valid event
	///handle (but we cannot simply get a valid event handle on Windows 7 e.g.!) which in turn yields a
	///suitable parameter mix for a successful call to NtWaitForAlertByThreadId, so our thread gets stuck forever.
	///We could hardcode that syscall number but then obviously, the whole thing would be taken ad absurdum...
	for (ULONG candNtReadFile = NT_SYSCALL_START; candNtReadFile < NT_SYSCALL_END; candNtReadFile++) {
		if ((syscallnumNtOpenFile == candNtReadFile) ||
			(syscallnumNtClose == candNtReadFile) ||
			(syscallnumNtQueryInformationFile == candNtReadFile))
			continue;	///Skip the ones we already know...

		ioSb.Status = 0xF000000D;
		*(PUSHORT)pNtdllBuffer = 0x0;
		status = syscallStub(candNtReadFile, hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, (ULONG)ntdllSize, NULL, NULL);
		if (0xF000000D == ioSb.Status)	///This test has an extremely strong filtering behavior!
			continue;

		if (status)
			continue;

		*pDebugBuffer = 6;
		if (IMAGE_DOS_SIGNATURE == *(PUSHORT)pNtdllBuffer) {
			status = STATUS_SUCCESS;
			*pDebugBuffer = (ULONG)ntdllSize;
			break;
		}
	}

	syscallStub(syscallnumNtClose, hFile);
	return status;
}

///Pretty self explaining... one provides a valid RVA and a base address corresponding to an on-disk image
///and gets a pointer to the file offset which at the same time is a valid pointer into the on-disk like
///memory buffer.
PVOID rvaToFileOffset(_In_ ULONG rva, _In_ PVOID pMemoryBase) {
	PIMAGE_NT_HEADERS pNtdllPeHdr = (PIMAGE_NT_HEADERS)((PUCHAR)pMemoryBase + ((PIMAGE_DOS_HEADER)pMemoryBase)->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSecHdr = IMAGE_FIRST_SECTION(pNtdllPeHdr);
	for (ULONG i = 0; i < pNtdllPeHdr->FileHeader.NumberOfSections; i++) {
		if ((pFirstSecHdr[i].VirtualAddress <= rva) && (rva < pFirstSecHdr[i].VirtualAddress + pFirstSecHdr[i].Misc.VirtualSize))
			return  (PUCHAR)pMemoryBase + rva + pFirstSecHdr[i].PointerToRawData - pFirstSecHdr[i].VirtualAddress;
	}
	return NULL;
}

///Takes the NTAPI name (and its length) and retrieves the corresponding syscall number.
///Could be written less complicated and smaller using strcmp routine and zero-terminated
///strings in the lookup table.
ULONG ntapiLookup(const char* pNtXxxApiName, SIZE_T nameLen) {
	USHORT currLen = 0;
	BOOLEAN stringsAreEqual = FALSE;
	char* pCurrPos = sg_pSyscallTable + 4;
	USHORT desiredApiLen = (USHORT)nameLen - sizeof(ANSI_NULL);

	if (!pNtXxxApiName || !desiredApiLen)
		return NT_INVALID_SYSCALL;

	for (ULONG i = 0; i < *(PULONG)sg_pSyscallTable; i++) {
		currLen = *(PUSHORT)pCurrPos;
		pCurrPos += 2;
		if (desiredApiLen != currLen)
			stringsAreEqual = FALSE;
		else
			stringsAreEqual = (BOOLEAN)mymemcmp(pCurrPos, (char*)pNtXxxApiName, currLen);

		pCurrPos += currLen;
		if (stringsAreEqual){
			if (NT_INVALID_SYSCALL > ((PULONG)pCurrPos)[1])
				return ((PULONG)pCurrPos)[1];
			else
				return NT_INVALID_SYSCALL;
		}

		pCurrPos += 8;
	}

	return NT_INVALID_SYSCALL;
}

///Dumps all NtXxx functions along with its RVA and syscall number into a PE internal buffer.
///RVA gets dumped too so we could easily extend this function for use with non-NtXxx functions
///like KiUserCallbackDispatcher, RtlAdjustPrivileges or LdrLoadDll.
///This would, however, require us to load the DLL as an executable image because the indirect calls within these
///non-NtXxx functions often look like "call qword ptr [__imp__NtXxx]" or "mov rcx, qword ptr [__imp__AnyDataSymbol]"
///which would need to have the IAT and data section of the ntdll correctly loaded.
NTSTATUS createNtapiLookupTable(PVOID pRawNtdllBase) {
	PIMAGE_NT_HEADERS64 pNtdllPeHeader = NULL;
	ULONG rvaNtdllExportDirectory = 0x0;
	PIMAGE_EXPORT_DIRECTORY pNtdllExportDirectory = NULL;
	PULONG pNameRvaArray = NULL;
	PUSHORT pNameOrdinalArray = NULL;
	PULONG pFunctionRvaArray = NULL;
	char* pCurrName = NULL;
	ULONG rvaCurrentFunction = 0x0;
	PVOID pDesiredFunctionAddress;
	SIZE_T currStringLen = 0;
	char* pCurrPos = NULL;

	pNtdllPeHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)pRawNtdllBase + ((PIMAGE_DOS_HEADER)pRawNtdllBase)->e_lfanew);
	if ((pNtdllPeHeader->Signature != IMAGE_NT_SIGNATURE) ||
		(pNtdllPeHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
		(pNtdllPeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
		return STATUS_INVALID_IMAGE_WIN_64;

	if (!pNtdllPeHeader->OptionalHeader.NumberOfRvaAndSizes)
		return STATUS_RESOURCE_DATA_NOT_FOUND;

	rvaNtdllExportDirectory = pNtdllPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	pNtdllExportDirectory = (PIMAGE_EXPORT_DIRECTORY)rvaToFileOffset(rvaNtdllExportDirectory, pRawNtdllBase);
	if (!pNtdllExportDirectory)
		return STATUS_NOT_EXPORT_FORMAT;

	pNameRvaArray = (PULONG)rvaToFileOffset(pNtdllExportDirectory->AddressOfNames, pRawNtdllBase);
	pNameOrdinalArray = (PUSHORT)rvaToFileOffset(pNtdllExportDirectory->AddressOfNameOrdinals, pRawNtdllBase);
	pFunctionRvaArray = (PULONG)rvaToFileOffset(pNtdllExportDirectory->AddressOfFunctions, pRawNtdllBase);
	if (!pNameRvaArray || !pNameOrdinalArray || !pFunctionRvaArray)
		return STATUS_INVALID_IMAGE_FORMAT;

	pCurrPos = sg_pSyscallTable + 4;
	for (ULONG i = 0; i < pNtdllExportDirectory->NumberOfNames; i++) {
		pCurrName = (char*)rvaToFileOffset(pNameRvaArray[i], pRawNtdllBase);
		if (!pCurrName)
			continue;

		if(('N' == pCurrName[0]) && ('t' == pCurrName[1])) {
			rvaCurrentFunction = pFunctionRvaArray[pNameOrdinalArray[i]];
			rvaToFileOffset(rvaCurrentFunction, pRawNtdllBase);
			pDesiredFunctionAddress = rvaToFileOffset(rvaCurrentFunction, pRawNtdllBase);
			if (pDesiredFunctionAddress) {
				currStringLen = strlen(pCurrName);
				*(PUSHORT)pCurrPos = (USHORT)currStringLen;
				pCurrPos += 2;
				__movsb((PUCHAR)pCurrPos, (PUCHAR)pCurrName, currStringLen);
				pCurrPos += currStringLen;
				*(PULONG)pCurrPos = rvaCurrentFunction;
				*(PULONG)(pCurrPos + 4) = ((PNT_SYSCALL_STUB)pDesiredFunctionAddress)->syscallNumber;
				pCurrPos += 8;
				///Save the number of NtXxx functions...
				(*(PULONG)sg_pSyscallTable)++;
			}
		}
	}

	///This means we have never found ANY NtXxx function. Therefore the user needs to make sure (using Process Hacker e.g.)
	///that the ntdll file hase been loaded correctly (See Memory tab in PH).
	if (!*(PULONG)sg_pSyscallTable)
		return STATUS_INTERNAL_ERROR;

	///A pristine ntdll should have at least 64 NtXxx functions IMHO...
	if(0x40 > *(PULONG)sg_pSyscallTable)
		return STATUS_PARTIAL_COPY;

	return STATUS_SUCCESS;
}

///This is just for demo reasons: It unmaps everything executable within the processes VA space and then exits.
void selfUnmap(void) {
	PVOID pModuleBases[0x20];
	ULONG i = 0;
	ULONG ntUnmapViewOfFileNum = ((PNT_SYSCALL_STUB)NtUnmapViewOfSection)->syscallNumber;
	PVOID pSelfBase = NtCurrentPeb()->ImageBaseAddress;
	PLDR_DATA_TABLE_ENTRY pFirstEntry = (PLDR_DATA_TABLE_ENTRY)(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink);
	PLDR_DATA_TABLE_ENTRY pCurrEntry = pFirstEntry;

	for (; i < sizeof(pModuleBases) / sizeof(PVOID); i++) {
		if (pSelfBase != pCurrEntry->DllBase)
			pModuleBases[i] = pCurrEntry->DllBase;
		else
			i--;

		pCurrEntry = (PLDR_DATA_TABLE_ENTRY)pCurrEntry->InLoadOrderLinks.Flink;
		if (pFirstEntry == pCurrEntry)
			break;
	}

	for (ULONG j = 0; j < i; j++)
		if (syscallStub(ntUnmapViewOfFileNum, INVALID_HANDLE_VALUE, pModuleBases[j], 0x2978634294367583, 0xaecfaefceaaebaef))
			break;
}

///We don't have the ntdll loaded as an executable image so we cannot use the ntdll's RtlAdjustPrivilege.
NTSTATUS myRtlAdjustPrivileges(ULONG Privilege) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	ULONG returnLength = 0;
	TOKEN_PRIVILEGES tokenPrivs;

	status = syscallStub(ntapiLookup("NtOpenProcessTokenEx", sizeof("NtOpenProcessTokenEx")), INVALID_HANDLE_VALUE, TOKEN_ALL_ACCESS, 0, &hToken);
	if (status)
		return status;

	tokenPrivs.PrivilegeCount = 1;
	tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tokenPrivs.Privileges[0].Luid.LowPart = Privilege;
	status = syscallStub(ntapiLookup("NtAdjustPrivilegesToken", sizeof("NtAdjustPrivilegesToken")), hToken, FALSE, &tokenPrivs, sizeof(tokenPrivs), &tokenPrivs, &returnLength);
	return status;
}

///If everything has been set up sucessfully, we do just a small test
///which terminates all programs it can get PROCESS_FULL_ACCESS to.
///Furthermore, it maps ntoskrnl.exe as an executable image.. even if that's not too useful at the moment...
NTSTATUS testNtapiTable(void) {
	UNICODE_STRING uMyNtdll;
	PIO_STATUS_BLOCK ioSb;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES procAttr;
	LARGE_INTEGER interval;

	PVOID pNtosBase = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	SIZE_T viewSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hCurrPid = NtCurrentTeb()->ClientId.UniqueProcess;
	WCHAR szMyNtdll[] = L"\\systemroot\\system32\\ntoskrnl.exe";
	HANDLE hSection = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;

	///The copy of the pristine ntdll data has succeeded and can now be found in the syscall table.
	///Of course, we display this message by just using this table...
	syscallStub(ntapiLookup("NtRaiseHardError", sizeof("NtRaiseHardError")), STATUS_FT_READ_FROM_COPY, 0, 0, NULL, 0, (PULONG)&status);

	uMyNtdll.Buffer = szMyNtdll;
	uMyNtdll.LengthInBytes = sizeof(szMyNtdll) - sizeof(UNICODE_NULL);
	uMyNtdll.MaximumLengthInBytes = sizeof(szMyNtdll);
	InitializeObjectAttributes(&objAttr, &uMyNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = syscallStub(ntapiLookup("NtOpenFile", sizeof("NtOpenFile")), &hFile, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioSb, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
	if (status)
		return status;

	status = syscallStub(ntapiLookup("NtCreateSection", sizeof("NtCreateSection")), &hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
	if (status)
		return status;

	status = syscallStub(ntapiLookup("NtMapViewOfSection", sizeof("NtMapViewOfSection")), hSection, INVALID_HANDLE_VALUE, &pNtosBase, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READONLY);
	if (status)
		return status;

	///Clearly, the ntoskrnl.exe image could not be loaded at its kernel 0xFFFFXXXXXXXXXXXXXX base...
	dispError(STATUS_IMAGE_NOT_AT_BASE);

	cid.UniqueThread = NULL;
	interval.QuadPart = -2000000;
	InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);

	///Will kill Windows 7.
	for (ULONG i = 0; i < 0x28; i++)
		status = myRtlAdjustPrivileges(i);

	for (;;) {
		for (ULONG_PTR i = 0; i < 0x8000; i += 4) {
			if (hCurrPid != (HANDLE)i) {
				cid.UniqueProcess = (HANDLE)i;
				status = syscallStub(ntapiLookup("NtOpenProcess", sizeof("NtOpenProcess")), &hProcess, PROCESS_ALL_ACCESS, &procAttr, &cid);
				if (!status) {
					syscallStub(ntapiLookup("NtDelayExecution", sizeof("NtDelayExecution")), FALSE, &interval);
					syscallStub(ntapiLookup("NtTerminateProcess", sizeof("NtTerminateProcess")), hProcess, STATUS_FATAL_APP_EXIT);
				}
			}
		}
	}
}

///Attempts to read the ntdll.dll file and then tries to dump the NtXxx functions
NTSTATUS initializeSyscallTable(void) {
	PVOID pNtdll = sg_pRawNtdll;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG dbgBuf = 0x0;
	ULONG firstOccurence = 0x0;

	///Set up ourselves...
	status = performCoreInitialization(pNtdll, NTDLL_MAX_SIZE, &dbgBuf, &firstOccurence);
	if (status) {
		if (firstOccurence)
			dispError((NTSTATUS)dbgBuf);

		return status;
	}

	///Now create the syscall table in order to be able to use all NtXxx functions.
	return createNtapiLookupTable(pNtdll);
}

void mymain(void){
	NTSTATUS status = STATUS_PENDING;

	///The requested operation waits until you click a button.
	dispError(status);
	selfUnmap();
	///No image (except the own one) can be found...
	dispError(STATUS_SECTION_NOT_IMAGE);

	///Initialize everything...
	status = initializeSyscallTable();
	if (status) {
		dispError(status);
		return;
	}

	///...and demonstrate that we have hopefully succeeded.
	status = testNtapiTable();
	if (status)
		dispError(status);
}
