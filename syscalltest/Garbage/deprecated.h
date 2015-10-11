//UCHAR g_fpMySyscall[] = { 0x89, 0xC8, 0x49, 0x89, 0xD2, 0x4C, 0x89, 0xC2, 0x4D, 0x89, 0xC8, 0x4D, 0x31, 0xC9, 0x4C, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x83, 0xC4, 0x08, 0x90, 0x0F, 0x05, 0x48, 0x83, 0xEC, 0x08, 0xC3 };
//		for (ULONG candNtQueryInformationFileOrNtClose = NT_SYSCALL_START; candNtQueryInformationFileOrNtClose < NT_SYSCALL_END; candNtQueryInformationFileOrNtClose++) {
//			//if(syscallnumNtClose == candNtQueryInformationFileOrNtClose)
//				
//			RtlSecureZeroMemory(&ntdllInfo, sizeof(FILE_STANDARD_INFORMATION));
//			ioSb.Pointer = NULL;
//			status = syscallStub(candNtQueryInformationFileOrNtClose, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
//			if (status)
//				continue;
//void asdf(NTSTATUS status) {
//	ULONGLONG blah;
//	ULONG bleh;
//	NtRaiseHardError(status, 1, 0, (PULONG_PTR)&blah, 0, &bleh);
//}
//			if ((NTDLL_MIN_SIZE < ntdllInfo.EndOfFile.QuadPart) &&
//				(ntdllInfo.EndOfFile.QuadPart <= ntdllInfo.AllocationSize.QuadPart) &&
//				(ntdllInfo.AllocationSize.QuadPart <= NTDLL_MAX_SIZE)) {
//NTSTATUS createPristineSyscallTable(PVOID pFilledNtdllBuffer, SIZE_T pBufferSize) {
//	USHORT lineNum = 0;
//	NTSTATUS status = STATUS_UNSUCCESSFUL;
//	PIMAGE_NT_HEADERS64 pNtdllPeHdr = NULL;
//NtMapViewOfSection()
//if(status)
//NtRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, a, 0, (PULONG)&status);
//ULONGLONG a[1];
//UNICODE_STRING us = { 16, 18, L"Hello =D" };
//ULONGLONG a[3] = { 0x7698, 0x5876587658765, 0 };
//a[2] = (ULONGLONG)&us;
//a[0] = (ULONGLONG)&us;
//	syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//	if (!pFilledNtdllBuffer || !pBufferSize)
//		return STATUS_INVALID_PARAMETER;
//
//	createNtapiLookupTable(pFilledNtdllBuffer);
//	syscallStub(ntapiLookup("NtRaiseHardError"), STATUS_FT_READ_FROM_COPY, 0, 0, NULL, 0, (PULONG)&status);
//
//	PLDR_DATA_TABLE_ENTRY pFirstEntry = (PLDR_DATA_TABLE_ENTRY)(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink);
//	PLDR_DATA_TABLE_ENTRY pCurrEntry = (PLDR_DATA_TABLE_ENTRY)pFirstEntry->InLoadOrderLinks.Flink;
//	BOOLEAN queryFreeMem = FALSE;
//	PVOID pCurrAddress = NULL;
//
//	MEMORY_BASIC_INFORMATION freeMemInfo;
//	ULONGLONG resultLen = 0;
//	MEMORY_BASIC_VLM_INFORMATION imageOrMappingInfo;
//	RtlSecureZeroMemory(&freeMemInfo, sizeof(MEMORY_BASIC_INFORMATION));
//	RtlSecureZeroMemory(&imageOrMappingInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION));
//	//syscallStub(g_ntapiList[11].syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//	syscallStub(ntapiLookup("NtRaiseHardError"), STATUS_ACCESS_DISABLED_BY_POLICY_PATH, 0, 0, NULL, 0, (PULONG)&status);
//	for (;;) {
//		if (queryFreeMem)
//			status = syscallStub(ntapiLookup("NtQueryVirtualMemory"), INVALID_HANDLE_VALUE, pCurrAddress, MemoryBasicInformation, &freeMemInfo, sizeof(MEMORY_BASIC_INFORMATION), &resultLen);
//		else
//			status = syscallStub(ntapiLookup("NtQueryVirtualMemory"), INVALID_HANDLE_VALUE, pCurrAddress, MemoryBasicVlmInformation, &imageOrMappingInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION), &resultLen);
//		if (STATUS_INVALID_ADDRESS == status) {
//			queryFreeMem = TRUE;
//			continue;
//		}
//		if (STATUS_INVALID_PARAMETER == status)
//			break;
//
//		if (status)
//			return status;
//
//		if (queryFreeMem) {
//			//if(MEM_MAPPED == freeMemInfo.State)
//				//myWPrintf(&lineNum, L"NtOpenProcess address %p, %p", freeMemInfo.AllocationBase, freeMemInfo.BaseAddress);
//			//freeMemInfo.Type
//			pCurrAddress = (PUCHAR)pCurrAddress + freeMemInfo.RegionSize;
//			queryFreeMem = FALSE;
//			continue;
//		}
//		else {
//			pCurrAddress = (PUCHAR)pCurrAddress + imageOrMappingInfo.SizeOfImage;
//			queryFreeMem = FALSE;
//		}
//
//		//myWPrintf(&lineNum, L"NtOpenProcess address %llX, %p", imageOrMappingInfo.ImageBase, imageOrMappingInfo.Type);
//		//if(imageOrMappingInfo.)
//
//		if ((MEM_IMAGE != imageOrMappingInfo.Type) &&
//			(MEM_MAPPED != imageOrMappingInfo.Type) &&
//			(SEC_COMMIT != imageOrMappingInfo.Type))
//		//	
//			continue;
//		//}
//		//syscallStub(ntapiLookup("NtRaiseHardError"), STATUS_ACCESS_DISABLED_BY_POLICY_PATH, 0, 0, NULL, 0, (PULONG)&status);
//			//continue;
//		//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//		//myWPrintf(&lineNum, L"NtOpenProcess address %llX, %p", imageOrMappingInfo.ImageBase, imageOrMappingInfo.Type);
//		if (NtCurrentPeb()->ImageBaseAddress != (PVOID)imageOrMappingInfo.ImageBase) {
//			//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//			status = syscallStub(ntapiLookup("NtUnmapViewOfSection"), INVALID_HANDLE_VALUE, (PVOID)imageOrMappingInfo.ImageBase);
//			//if (status)
//			
//				//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//		}
//
//		//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//		//syscallStub(g_ntapiList[10].apiInfo.syscallNum, INVALID_HANDLE_VALUE);
//
//		//myWPrintf(&lineNum, L"NtOpenProcess address %llX, %p", imageOrMappingInfo.ImageBase, imageOrMappingInfo.Type);
//
//		//status = NtProtectVirtualMemory(hProcess, (PVOID)&imageOrMappingInfo.ImageBase, &fullImageHdrSize, PAGE_READONLY, &oldProt);
//		//if (status)
//		//	continue;
//
//		//DebugPrint2A("memVlmInfo.ImageBase: %p", imageOrMappingInfo.ImageBase);
//		//status = NtReadVirtualMemory(hProcess, (PVOID)imageOrMappingInfo.ImageBase, sg_pFullImageHdr, sizeof(sg_pFullImageHdr), &fullImageHdrSize);
//		//if (status)
//		//	continue;
//
//		//pPeHdr64 = (PIMAGE_NT_HEADERS64)(sg_pFullImageHdr + ((PIMAGE_DOS_HEADER)sg_pFullImageHdr)->e_lfanew);
//		//if (IMAGE_NT_SIGNATURE != pPeHdr64->Signature)
//		//	continue;
//
//		//pFirstSecHdr = IMAGE_FIRST_SECTION(pPeHdr64);
//		//for (ULONG i = 0; i < pPeHdr64->FileHeader.NumberOfSections; i++) {
//		//	currSecHdr = pFirstSecHdr[i];
//		//	DebugPrint2A("%lX", currSecHdr.Characteristics);
//		//	if (currSecHdr.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
//		//		DebugPrint2A("Executable section starts @ %p with size %llX", (sg_pFullImageHdr + PAGE_ROUND_UP(currSecHdr.VirtualAddress)), currSecHdr.Misc.VirtualSize);
//		//	}
//		//}
//	}
//	syscallStub(ntapiLookup("NtRaiseHardError"), status, 0, 0, NULL, 0, (PULONG)&status);
//	//return STATUS_SUCCESS;
//	//;
//
//
//
//	//while (pFirstEntry != pCurrEntry){
//	//	if (NtCurrentPeb()->ImageBaseAddress != pCurrEntry->DllBase) {
//	//		status = syscallStub(g_ntapiList[12].apiInfo.syscallNum, INVALID_HANDLE_VALUE, pCurrEntry->DllBase);
//	//		if (status)
//	//			syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//	//	}
//
//	//	syscallStub(g_ntapiList[10].apiInfo.syscallNum, INVALID_HANDLE_VALUE);
//	//	pCurrEntry = (PLDR_DATA_TABLE_ENTRY)pCurrEntry->InLoadOrderLinks.Flink;
//	//}
//	//syscallStub(g_ntapiList[10].apiInfo.syscallNum, INVALID_HANDLE_VALUE);
//	////PVOID pNtdllBase = ((PLDR_DATA_TABLE_ENTRY)(((PLDR_DATA_TABLE_ENTRY)(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink))->InLoadOrderLinks.Flink))->DllBase;
//	////status = syscallStub(g_ntapiList[12].apiInfo.syscallNum, INVALID_HANDLE_VALUE, pNtdllBase);
//	////if(status)
//	////	syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//
//	////syscallStub(g_ntapiList[10].apiInfo.syscallNum, INVALID_HANDLE_VALUE);
//	////myWPrintf(&lineNum, L"NtOpenProcess address %llX", (PUCHAR)pNtdllBase + g_ntapiList[4].apiInfo.apiRva);
//	
//
//	//syscallStub(g_ntapiList[11].apiInfo.syscallNum, STATUS_XML_PARSE_ERROR, 0, 0, NULL, 0, (PULONG)&status);
//	//syscallStub(g_ntapiList[0].apiInfo.syscallNum, INVALID_HANDLE_VALUE, STATUS_SUCCESS);
//	UNICODE_STRING uMyNtdll;
//	//UNICODE_STRING us = { 16, 18, L"Hello =D" };
//	//ULONGLONG a[3] = { 0x7698, 0x5876587658765, 0 };
//	//a[2] = (ULONGLONG)&us;
//	//NtRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, a, 0, (PULONG)&status);
//	//ULONGLONG a[1];
//	//a[0] = (ULONGLONG)&us;
//	PIO_STATUS_BLOCK ioSb;
//	PVOID pNtosBase = NULL;
//	OBJECT_ATTRIBUTES objAttr;
//	SIZE_T viewSize = 0;
//	HANDLE hFile = INVALID_HANDLE_VALUE;
//	WCHAR szMyNtdll[] = L"\\systemroot\\system32\\ntoskrnl.exe";
//	uMyNtdll.Buffer = szMyNtdll;
//	uMyNtdll.LengthInBytes = sizeof(szMyNtdll) - sizeof(UNICODE_NULL);
//	uMyNtdll.MaximumLengthInBytes = sizeof(szMyNtdll);
//	InitializeObjectAttributes(&objAttr, &uMyNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
//	status = syscallStub(ntapiLookup("NtOpenFile"), &hFile, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioSb, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	//if(status)
//	
//	//	syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//	//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//	HANDLE hSection = INVALID_HANDLE_VALUE;
//	status = syscallStub(ntapiLookup("NtCreateSection"), &hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
//	//NtMapViewOfSection()
//	HANDLE hProcess = INVALID_HANDLE_VALUE;
//	CLIENT_ID cid;
//	cid.UniqueThread = NULL;
//	LARGE_INTEGER interval;
//	interval.QuadPart = -2000000;
//	//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//	status = syscallStub(ntapiLookup("NtMapViewOfSection"), hSection, INVALID_HANDLE_VALUE, &pNtosBase, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READONLY);
//	syscallStub(ntapiLookup("NtRaiseHardError"), status, 0, 0, NULL, 0, (PULONG)&status);
//	OBJECT_ATTRIBUTES procAttr;
//	
//	InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);
//	go:
//	for (ULONG_PTR i = 0; i < 0x10000; i+=4) {
//		if (hCurrPid != (HANDLE)i) {
//			cid.UniqueProcess = (HANDLE)i;
//			status = syscallStub(ntapiLookup("NtOpenProcess"), &hProcess, PROCESS_ALL_ACCESS, &procAttr, &cid);
//			if (!status) {
//				syscallStub(ntapiLookup("NtDelayExecution"), FALSE, &interval);
//				//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 0, 0, NULL, 0, (PULONG)&status);
//				syscallStub(ntapiLookup("NtTerminateProcess"), hProcess, PROCESS_ALL_ACCESS, NULL, &cid);
//			}	
//		}
//	}
//	goto go;
//	return STATUS_SUCCESS;
//}
//				///The retrieved ntdll.dll size is reasonable, we are likely to have figured
//				///out the NtOpenFile system call correctly.now attempt to read the file into caller-allocated buffer.
//			}
//if (status)
//myWPrintf(&lineNum, L"Unexpected program exit.%lX", status);
//for (ULONG i = 0; i < 0x1000; i++) {
//	return status;

//status = createPristineSyscallTable(pNtdll);
//if(status)
//myWPrintf(&lineNum, L"Failed to create syscall table! %lX", status);
//CONTEXT ctx;
//ctx.
//}

//status = STATUS_SERVICE_NOTIFICATION;
//syscallStub(g_ntapiList[11].apiInfo.syscallNum, status, 1, 1, a, 0, (PULONG)&status);
//
//STATUS_SERVICE_NOTIFICATION;
//NtMapVi
//NtCreateSection()
//LdrUnloadDll
//typedef struct _NTAPI_FUNCTION_LIST {
//	NTAPI_ENTRY apiEntry[10];
//	//NTAPI_ENTRY ntTerminateProcess;
//	//NTAPI_ENTRY ntDelayExecution;
//	//NTAPI_ENTRY ntWriteVirtualMemory;
//	//NTAPI_ENTRY ntCreateUserProcess;
//	//NTAPI_ENTRY ntOpenProcess;
//	//NTAPI_ENTRY ntProtectVirtualMemory;
//	//NTAPI_ENTRY ntReadVirtualMemory;
//	//NTAPI_ENTRY ntWaitForWorkViaWorkerFactory;
//	//NTAPI_ENTRY kiUserExceptionDispatcher;
//	//NTAPI_ENTRY kiUserInvertedFunctionTable;
//} NTAPI_FUNCTION_LIST, *PNTAPI_FUNCTION_LIST;
//NtProtectVirtualMemory()
////for (ULONG i = 0; i < sizeof(NTAPI_FUNCTION_LIST) / sizeof(NTAPI_ENTRY); i++) {
////	pFunctionList[i].
////}
//	//PIMAGE_DATA_DIRECTORY pNtdllDataDir = &pNtdllPeHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
//	//PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
//	//PIMAGE_SECTION_HEADER pFirstSecHdr = IMAGE_FIRST_SECTION(pNtdllPeHdr);
//	//ULONG currBias = 0;
//	////pFirstSecHdr->Misc.VirtualSize
//
//	//myWPrintf(&lineNum, L"oaduhiadusi%lX", pNtdllDataDir->VirtualAddress);
//	//pExportDir = (PIMAGE_EXPORT_DIRECTORY)rvaToFileOffset(pNtdllDataDir->VirtualAddress, pFilledNtdllBuffer);
//	
//	myWPrintf(&lineNum, L"Number0fFuncs: %d", pExportDir->NumberOfFunctions);
//
//	//PULONG pAddressOfNames = (PULONG)(pExportDirectory->AddressOfNames + pBaseAddress - rdataBias);
//	//PUSHORT pAddressOfNameOrdinals = (PUSHORT)(pExportDirectory->AddressOfNameOrdinals + pBaseAddress - rdataBias);
//	//PULONG pAddressOfFunctions = (PULONG)(pExportDirectory->AddressOfFunctions + pBaseAddress - rdataBias);
//	//RtlUnicodeStringInit;
//	
//	ULONG currNameRva = 0;
//	ULONG currFunctionRva = 0;
//	SIZE_T stringLen = 0;
//	PVOID pDesiredFunc = NULL;
//	PULONG pNameRvaArray = (PULONG)rvaToFileOffset(pExportDir->AddressOfNames, pFilledNtdllBuffer);
//	PUSHORT pNameOrdinalArray = (PUSHORT)rvaToFileOffset(pExportDir->AddressOfNameOrdinals, pFilledNtdllBuffer);
//	PULONG pFunctionRvaArray = (PULONG)rvaToFileOffset(pExportDir->AddressOfFunctions, pFilledNtdllBuffer);
//	char* pCurrName = NULL;
//	USHORT currOrdinal = 0;
//	
//	for (ULONG i = 0; i < pExportDir->NumberOfNames; i++) {
//		pCurrName = (char*)rvaToFileOffset(pNameRvaArray[i], pFilledNtdllBuffer);
//		myWPrintf(&lineNum, L"pNameRvaArray: 0x%p, offset of pExportDir->Name: 0x%p", pNameRvaArray, rvaToFileOffset(pExportDir->Name, pFilledNtdllBuffer));
//		//myWPrintf(&lineNum, L"len: %ld", (SIZE_T)pNameRvaArray - (SIZE_T)rvaToFileOffset(pExportDir->Name, pFilledNtdllBuffer));
//		//status = RtlStringCbLengthA(pCurrName, pNameRvaArray[0] - pExportDir->Name, &stringLen);
//		//if (status) {
//		//	NtSuspendProcess(INVALID_HANDLE_VALUE);
//		//	return status;
//		//}
//		
//		//__movsb(pCurrName, pNameOrdinalArray, 67);
//
//		//myWPrintf(&lineNum, L"pFileOffset = %llX", stringLen);
//		if (RtlEqualMemory(pCurrName, "NtSuspendProcess", sizeof("NtSuspendProcess") -sizeof(ANSI_NULL))) {
//			currFunctionRva = pFunctionRvaArray[pNameOrdinalArray[i]];
//			pDesiredFunc = rvaToFileOffset(currFunctionRva, pFilledNtdllBuffer);
//			myWPrintf(&lineNum, L"pFileOffset = %p", pDesiredFunc);
//			syscallStub(((PULONG)pDesiredFunc)[1], INVALID_HANDLE_VALUE);
//			//return (LONG);
//		}
//
//		//RtlCompareMemory()
//
//
//		//RtlEqualString()
//		//myWPrintf(&lineNum, L"%s", ;
//	}
//	//tlStringCbLengthA
//	//while (i < pExportDir->NumberOfNames) {
//	//	currNameRva = pAddressOfNames[i];
//	//	currOrdinal = pAddressOfNameOrdinals[i];
//	//	pCurrName = currNameRva + pBaseAddress - rdataBias;
//
//	//	if (!strncmp((LPCSTR)pCurrName, pDesiredFunction, NameLength)) {
//	//		currFunctionRva = pAddressOfFunctions[currOrdinal];
//	//		functionAddress = (ULONGLONG)(currFunctionRva + pBaseAddress - textBias);
//	//		return functionAddress;
//	//	}
//	//	i++;
//	//}
//	//functionAddress = 0x0;
//	//return functionAddress;
//	//pExportDir->Name
//	////*ppExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDataDirectory->VirtualAddress + *ppBaseAddress - *pRdataBias);
//	//NtRaiseHardError(0, 0, 0, NULL, 0, (PULONG)&status);
//
//	//pNameRvaArray = (PULONG)((PUCHAR)pImageFileBase + pExportDirectory->AddressOfNames);
//	//maxReadSize = pExportDirectory->NumberOfNames * sizeof(ULONG);
//	//status = validatePePointer(pImageFileBase, pNameRvaArray, maxReadSize, FALSE);
//	//if (status)
//	//	return status;
//
//	/////Since NumberOfNames can be any value, we need to roughly estimate the exportSize
//	/////according to the combined sizes of the three export describing arrays.
//	/////If this yields to greater export size than the claimed export size, the image must be rejected.
//	//minExportSize = sizeof(ULONG) * pExportDirectory->NumberOfFunctions + pExportDirectory->NumberOfNames * sizeof(ULONG) + sizeof(USHORT) + sizeof(ANSI_NULL);
//	//if (exportSize <= minExportSize)
//	//	return STATUS_INVALID_IMAGE_FORMAT;
//
//	/////It is NOT guaranteed, that an entry in the name RVA array at position 'n' has a value
//	/////which also orders as the n-th element in the entire name RVA range.
//	/////It is therefore not permissible to calculate the name length by simply doing
//	/////pNameRvaArray[n+1] - pNameRvaArray[n]. If we still want to make this assumption
//	/////the RVAs values must be sorted until they are in an ascending order.
//	/////By utilizing the last unused bytes of the caller-allocated buffer we avoid having
//	/////to allocate a buffer on our own. Doing the math above (see exportsize calculation)
//	/////one can prove that the safety margin is sufficient if we use the buffer in that way.
//	//piListBuffer = (PULONG)(pListBuffer + *pNeededBufferSize - pExportDirectory->NumberOfNames * sizeof(ULONG));
//	//RtlCopyMemory(piListBuffer, pNameRvaArray, pExportDirectory->NumberOfNames * sizeof(ULONG));
//	//qsort(piListBuffer, (ULONGLONG)pExportDirectory->NumberOfNames, sizeof(ULONG), mycompare);
//
//	/////Is it safe to read the module name?
//	//maxReadSize = pNameRvaArray[0] - pExportDirectory->Name;
//	//status = validatePePointer(pImageFileBase, (PVOID)((PUCHAR)pImageFileBase + pExportDirectory->Name), maxReadSize, FALSE);
//	//if (status)
//	//	return status;
//
//	//if (moduleNameSize < maxReadSize)
//	//	return STATUS_STACK_OVERFLOW;
//
//	//RtlCopyMemory(pModuleName, (PUCHAR)pImageFileBase + pExportDirectory->Name, maxReadSize);
//	//pModuleName[maxReadSize - 1] = 0x0;
//	//pListPointer = pListBuffer;
//	//printf_s("\nmodule name: %s", pModuleName);
//
//	//pNameRvaArray = piListBuffer;
//	//for (ULONG i = 0; i < pExportDirectory->NumberOfNames; i++) {
//	//	///Will none of the obtained name RVAs evaluate to an invalid name pointer?
//	//	if (!(exportSize + pDataDirectory->VirtualAddress > pNameRvaArray[i]))
//	//		return STATUS_INVALID_IMAGE_FORMAT;
//
//	//	pCurrName = (PUCHAR)pImageFileBase + pNameRvaArray[i];
//	//	///At the end of RVA array there is no longer a next name entry.
//	//	///There must by PE design a terminating zero though, which we're going to exploit
//	//	///in order to still have a valid name length.
//	//	if (pExportDirectory->NumberOfNames - 1 == i) {
//	//		int j = 0;
//	//		while (pCurrName[j])
//	//			j++;
//
//	//		nameLength = j;
//	//	}
//	//	else {
//	//		nameLength = (ULONGLONG)(pNameRvaArray[i + 1] - pNameRvaArray[i]/*pNextName - pCurrName*/) - 1;
//	//	}
//	//	///If for some reason the allocated buffer is about to be overran
//	//	///we print an error signature into the buffer and abort the scan.
//	//	///In regard of our thousands of sanity checks this surely denotes a major PE damage.
//	//	///Additionally, we break a little earlier to not have the failure overwrite the sorted RVAs.
//	//	if ((PUCHAR)piListBuffer <= pListPointer + nameLength + sizeof(WCHAR)) {
//	//		pCurrName = szError;
//	//		nameLength = sizeof(szError) - 1;
//	//		pListPointer = (PUCHAR)piListBuffer - (nameLength + sizeof(WCHAR));
//	//		///Indirect break, bail out.
//	//		i = pExportDirectory->NumberOfNames;
//	//	}
//
//	//	RtlCopyMemory(pListPointer, pCurrName, nameLength);
//	//	*(PWCHAR)&pListPointer[nameLength] = (WCHAR)0x0A0D;
//	//	pListPointer += nameLength + sizeof(WCHAR);
//	//}
////	pNtdllDataDir->VirtualAddress;
////	
////	pFirstSecHdr->Misc.
////	__C_specific_handler;
////	foundRdata = TRUE;
////	DebugPrintA("Found .rdata section, now calculating rdata bias!");
////
////	*pRdataBias = currSecHdr.VirtualAddress - currSecHdr.PointerToRawData;
////}
////	}
////
////	if (!foundText || !foundRdata) {
////		DebugPrintA("Fatal Error! Could not get one or both virtual-to-realaddress biases!");
////		return STATUS_INVALID_IMAGE_FORMAT;
////	}
////
////	DebugPrintA("rdataBias: 0x%llx, textBias: 0x%llX", *pRdataBias, *pTextBias);
////
////	DebugPrintA("Data Directory Begin: 0x%llx", (ULONGLONG)pDataDirectory);
////
////	*ppExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDataDirectory->VirtualAddress + *ppBaseAddress - *pRdataBias);
////	DebugPrintA("Export Directory Size: 0x%lx", (ULONG)pDataDirectory->Size);
////	DebugPrintA("Data Directory RVA: 0x%lx", (ULONGLONG)(pDataDirectory->VirtualAddress));
////	DebugPrintA("Func Count: 0x%llx", (ULONGLONG)(*ppExportDirectory));
////
////	return STATUS_SUCCESS;
////	//if (1 > pHdr64->OptionalHeader.NumberOfRvaAndSizes) {
////	//	DebugPrintA("Image doesn't have export directory!");
////	//	return 0x0;
////	//}
//USHORT lineNum = 0;
//ULONG ntCreateFileSyscallNum = 0x0;
//ULONG ntCloseSyscallNum = 0x0;
//ULONG ntQueryInformationFileSyscallNum = 0x0;
//status = NtContinue((PCONTEXT)status, FALSE);
//myWPrintf(&lineNum, L"Failed to create syscall table! %lX", status);
//NtSuspendProcess(INVALID_HANDLE_VALUE);
////	//PIMAGE_DATA_DIRECTORY pDataDirectory = &pHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
////	//PIMAGE_SECTION_HEADER pFirstSecHdr = IMAGE_FIRST_SECTION(pHdr64);
//	return STATUS_SUCCESS;
//}

//pFunctionList->kiUserExceptionDispatcher.apiInfo = ntapiNameToNtapiInfo(pFunctionList->kiUserExceptionDispatcher.pApiName, pFunctionList->kiUserExceptionDispatcher.nameLength, pFilledNtdllBuffer);

//char* test[6] = { "NtOpenProcess", "NtSetSystemInformation", "NtQueryInformationProcess", "NtDelayExecution", "NtQueryObject", "NtOpenSection" };

//test[3][2] = 0x56;
//for (int i = 0; i < sizeof(test) / sizeof(char*); i++)
//	myWPrintf(&lineNum, L"test: %s", test[i]);
//__debugbreak();
//syscallStub(ntapiNameToNtSyscallNum("NtSuspendProcess", sizeof("NtSuspendProcess"), pFilledNtdllBuffer), INVALID_HANDLE_VALUE);
//myTerminate();

//if(stu)


//initCoreSyscalls(&ntCreateFileSyscallNum, &ntCloseSyscallNum, &ntQueryInformationFileSyscallNum);
//if (status)
//	return status;

//status = createPristineNtdllInMemory(pNtdll, &);
//if (status)
//	return status;

//status = manualMapNtdll();
//	//RtlSecureZeroMemory(&ctx, sizeof(ctx));
//	//ctx.ContextFlags = CONTEXT_FULL;
////CONTEXT ctx;
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//status = syscallStub(0x1B3, &status, 0x5555555555555555, 0x9999999999999999);
//UNICODE_STRING us = { 16, 18, L"Hello =D" };

//ULONGLONG a[4] = { 0x7698, 0x5876587658765, 0, 0x3221451324 };
//a[0] = (ULONGLONG)&us;
//status = NtRaiseHardError(STATUS_FATAL_APP_EXIT, 1, 0, (PULONG_PTR)&status, 0, (PULONG)&status);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//asdf(status);

//	//ctx.Rsp = (ULONGLONG)&mymain- 9;
//	//ctx.Rip = (ULONGLONG)mymain + 5;
//	status = syscallStub(i, 0x100, FALSE, 0x5555555555555555, 0x9999999999999999);
//	if (status)
//		myWPrintf(&lineNum, L"%lXUnexpected program exit.%lX", i, status);
//}

//				candNtOpenFile = 0x1000;
//				break;
//			}else{
//				status = syscallStub(candNtQueryInformationFileOrNtClose, hFile);
//				if (STATUS_INVALID_HANDLE != status)
//					continue; 

//				status = syscallStub(candNtOpenFile, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//				if (status)	///If this now fails we have really a strange problem.
//					return status;	///We can't do much more about it so just exit.

//				syscallnumNtClose = candNtQueryInformationFileOrNtClose;
//			}
//		}
//	}
//}

//
//for (ULONG candNtReadFile = NT_SYSCALL_START; candNtReadFile < NT_SYSCALL_END; candNtReadFile++) {
//	status = syscallStub(candNtReadFile, hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, (ULONG)ntdllInfo.EndOfFile.QuadPart, NULL, NULL);
//	if (status)
//		continue;

//	if (IMAGE_DOS_SIGNATURE != ((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_magic) {
//		status = syscallStub(i, )
//	}
//	continue;

//	if ((4 >((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_lfanew) ||
//		((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_lfanew >= (ULONG)ntdllInfo.EndOfFile.QuadPart)
//		continue;

//	pNtdllPeHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)pNtdllBuffer + ((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_lfanew);
//	if ((pNtdllPeHdr->Signature != IMAGE_NT_SIGNATURE) ||
//		(pNtdllPeHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
//		(pNtdllPeHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
//		continue;

//	///
//	return STATUS_SUCCESS;
//	if (((PUCHAR)pNtdllBuffer > pNtdllPeHdr) ||
//		((PUCHAR)pNtdllPeHdr > (PUCHAR)pNtdllBuffer + (ULONGLONG)ntdllInfo.EndOfFile.QuadPart))
//		continue;

//ULONGLONG var1;

//var1 = (ULONGLONG)&var1;
//myWPrintf(&lineNum, L"KiUserCallbackDispatcher @ %p", KiUserCallbackDispatcher);
//myWPrintf(&lineNum, L"KiUserExceptionDispatcher @ %p", KiUserExceptionDispatcher);
//NtSuspendProcess(INVALID_HANDLE_VALUE);
//PPEB pPeb = NtCurrentPeb();
//myWPrintf(&lineNum, L"pPeb->KernelCallbackTable @ %p", pPeb->KernelCallbackTable);
//pPeb->KernelCallbackTable = pFuncArray;
//for (ULONG i=0; i < sizeof(pFuncArray) / sizeof(PVOID); i++)
//	pFuncArray[i] = (PVOID)myDispatch;
////__debugbreak();
//for (ULONG i = 0+0x1000; i < 700+0x1000; i++) {
//	myWPrintf(&lineNum, L"%dStatus: 0x%lX", i, syscallStub(i, 0xC0FF33BABE, 0xC0FFEEAFFE, 0x1337C00C1E, 0xEEEEEEEBCDD3, 0xFFFFFF897FFF8711));
//}
//if (status)
//	return;


//NtProtectVirtualMemory(INVALID_HANDLE_VALUE, )

//ULONGLONG memSize = PAGE_SIZE;
//OBJECT_ATTRIBUTES myCid;
//myCid.UniqueProcess = NULL;
//InitializeObjectAttributes(&myCid, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
//myCid.UniqueProcess = &status;
//status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, (PVOID)&syscallStub, 0, &memSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//if (status) {
//	myWPrintf(&lineNum, L"zuasdzic%pdzdc      0 %lX", &lineNum, status);
//	NtTerminateProcess(INVALID_HANDLE_VALUE, status);
//}
//__stosb;
//__debugbreak();
//mytest(7878678);
//__sto

//0x1bb1;
//0x5a;
//0xb6d39b61a3;
//0x17;
//ULONGLONG a[1];
//HANDLE hFile;
//UNICODE_STRING uNtdll;
//RtlInitUnicodeString(&uNtdll, L"\\systemroot\\system32\\ntdll.dll");
//UNICODE_STRING uKey;
//RtlInitUnicodeString(&uKey, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
//OBJECT_ATTRIBUTES fileAttr;
//IO_STATUS_BLOCK ioSb;
//a[0] = (ULONGLONG)&uNtdll;
//InitializeObjectAttributes(&fileAttr, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
////RtlMoveMemory(syscallStub, pShellcode, sizeof(pShellcode));
////g_fpNtRaiseHardError = (PNT_RAISE_HARD_ERROR)((ULONGLONG)syscallStub + 0x800);
////RtlMoveMemory(g_fpNtRaiseHardError, pNtRaiseHardError, sizeof(pNtRaiseHardError));
////NtSuspendProcess(INVALID_HANDLE_VALUE);
//OBJECT_ATTRIBUTES keyAttr;
//InitializeObjectAttributes(&keyAttr, &uKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
////DbgBreakPoint();
////NtCreateFile(0x55, &hFile, MAXIMUM_ALLOWED, &fileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
////status = syscallStub(23, 45,25,26);
////status = syscallStub(0x55, )
////syscallStub(0x1D, &hFile, KEY_READ, &keyAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
////syscallStub(0x10C, &hFile, KEY_READ, &keyAttr, REG_OPTION_NON_VOLATILE);
////NtOpenKeyEx

//hFile = (HANDLE)0xC0FFEEBABE;
////status = syscallStub(0x14D, 0xC0000007, 1, 1, a, 3, (PULONG)&status);
//	//NtCreateKey()
//ULONG ntCreateFileNum = 0;
//ULONG ntCloseNum = 0;

//for (ULONG i = 0; i < 500; i++) {
//	status = syscallStub(i, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//	if ((!status) && hFile && ((HANDLE)0xC0FFEEBABE != hFile) && (INVALID_HANDLE_VALUE != hFile)) {
//	if (status)
//		//myWPrintf(&lineNum, L"Core Initialization Failed! %lX", status);
//
//
//HANDLE hArbHandle = INVALID_HANDLE_VALUE;
//LARGE_INTEGER interval;
//interval.QuadPart = -10000000;
//go:
//myWPrintf(&lineNum, L"Please write the value of an arbitrary existing handle to %p!", &hArbHandle);
////NtSuspendProcess(INVALID_HANDLE_VALUE);
//
////for (ULONGLONG i = 0; i < 0x1000; i += 4) {
////	status = syscallStub(((PULONG)NtWaitForSingleObject)[1], i, FALSE, NULL);
////	//status = syscallStub(0x185, (HANDLE)i, NtCurrentPeb(), NtCurrentTeb(), 0xC0000022, 0x45723429);
////	myWPrintf(&lineNum, L"Handle:%llX, CompletionStatus = %lX", i, status);
//////	NtDelayExecution(FALSE, &interval);
////}
////NtQueryInformationFile()
//
////for (ULONG j = 0; j < NT_SYSCALL_END; j++) {
////	if (0xF == j)
////		continue;
//pNtdllPeHdr->OptionalHeader.
//if (ioSb.Status)
//	continue;
//status = syscallStub(syscallnumNtClose, hFile);
//if (status)
//	continue;

//__finally {
//PIMAGE_NT_HEADERS64 pNtdllPeHdr = NULL;
//myWPrintf(&lineNum, L"NtClose = 0x%lX", syscallnumNtClose);
//myWPrintf(&lineNum, L"candNtOpenFile: 0x%lX", candNtOpenFile);
//myWPrintf(&lineNum, L"Handled exception with %lX!", candNtOpenFile);
//}

//myWPrintf(&lineNum, L"API %lX completed with status %lX", candNtOpenFile, status);
//myWPrintf(&lineNum, L"235234524352435345");

//myWPrintf(&lineNum, L"qqqqqqqqqqqqqqq");

//if (fileFirstTimeOpened){
//	fileFirstTimeOpened = FALSE;
//	candNtOpenFile--;
//	continue;
//}





//myWPrintf(&lineNum, L"tiiuzzuigzgiugzui");


//		if()
//hFile = hTestHandle;
//ioSb.Pointer = NULL;
//RtlInitUnicodeString(&uNtdll, L"\\systemroot\\system32\\ntdll.dll");
//InitializeObjectAttributes(&fileAttr, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
//status = syscallStub(candNtOpenFile, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//if (status)
//	continue;
//myWPrintf(&lineNum, L"candNtQueryInformationFile: 0x%lX", candNtQueryInformationFile);
//myWPrintf(&lineNum, L"Handled exception with %lX!", candNtQueryInformationFile);
//myWPrintf(&lineNum, L"agzsui %lX %lX", ioSb.Status, candNtQueryInformationFile);
//myWPrintf(&lineNum, L"ntdllSize: 0x%llX", ntdllSize);
//candNtOpenFile = NT_INVALID_SYSCALL;
//myWPrintf(&lineNum, L"syscallnumNtClose = 0x%lX, hFile = %p", syscallnumNtClose, hFile);

//	myWPrintf(&lineNum, L"syscallnumNtOpenFile = 0x%lX, hFile = %p", syscallnumNtOpenFile, hFile);
//	//LARGE_INTEGER interval;
//	//hFile = (HANDLE)0x120;
//	//syscallnumNtOpenFile = candNtOpenFile;

//	//interval.QuadPart = -50000000;
//	//status = NtWaitForSingleObject(hFile, FALSE, &interval);
//	//if (status)
//	//	return status;
//	///After passing the checks, we know that the handle seems to be innocent and it is likely that we found NtOpenFile.
//	///However, next we must check if the handle is really valid, by trying to use it with an operation that must
//	///succeed: NtClose. This particulary necessary because a new API NtGetCurrentProcessorNumberEx can also provide us
//	///with a value that is not 0 and divisible by 4 looking like a valid handle.
//	///Note: If the interfering NtGetCurrentProcessorNumberEx call was to give us a low-number handle which
//	///happened to be the same as a handle we have inherited from parent process (e.g. \KnownDlls\* handle)
//	///we might be inadvertently closing this handle. This could lead to unexpected program behavior in worst case.
//	///Additionally, it might lead to a wrong asssumption about the true NtOpenFile number.
//	if (NT_INVALID_SYSCALL == syscallnumNtClose){
//		for (ULONG candNtClose = NT_SYSCALL_START; candNtClose < NT_SYSCALL_END; candNtClose++) {
//			if (syscallnumNtOpenFile == candNtClose)
//				continue;

//			///Try to call NtClose on the handle the first time.
//			status = syscallStub(candNtClose, hFile);
//			if (STATUS_HANDLE_NOT_CLOSABLE == status){	///We have found NtClose for sure but NtOpenFile provided us with a 
//				syscallnumNtClose = candNtClose;		///wrong (yet valid) handle value. We break the loop and note the NtClose
//				break;									///number so the next time we don't have to scan for it again.
//			}											

//			///Did it succeed? Then call it the second time with the very same syscall number.
//			status = syscallStub(candNtClose, hFile);
//			if (STATUS_INVALID_HANDLE != status)	///If we now don't receive C0000008 we have not yet closed the handle
//				continue;							///and consequently not found NtClose. We'll try on.

//			///Since we now closed the handle we need to open the file again using the
//			///previously found NtOpenFile number. As mentioned above our pointer targets might have become destroyed.
//			///Just paranoidly renew everything.
//			hFile = hTestHandle;
//			ioSb.Pointer = NULL;
//			RtlInitUnicodeString(&uNtdll, L"\\systemroot\\system32\\ntdll.dll");
//			InitializeObjectAttributes(&fileAttr, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
//			status = syscallStub(candNtOpenFile, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//			if (status)		
//				return status;	///We succeeded the first time but failed at the second attempt? Strange. We have a major problem. 

//			syscallnumNtClose = candNtClose;	///Save the found NtClose number in order to:
//												///==> Safely skip it in the following NtQueryInformationFile and NtReadFile number scans
//												///==> Be able to close the file if not needed anymore.
//			break;
//		}

//		if (NT_INVALID_SYSCALL == syscallnumNtClose)
//			///If NtClose did not return the expected results we assume that we must have called
//			///an interfering call (e.g. NtGetCurrentProcessorNumberEx). We need to further search for the
//			///true NtOpenFile number and can also forget all assumptions about NtClose.
//			continue;//return STATUS_RETRY;		///Possible improvement: Maybe, later continue the very outer loop...
//	}

//	myWPrintf(&lineNum, L"syscallnumNtClose = 0x%lX, hFile = %p", syscallnumNtClose, hFile);
//	for (ULONG candNtQueryInformationFile = NT_SYSCALL_START; candNtQueryInformationFile < NT_SYSCALL_END; candNtQueryInformationFile++){
//		if ((syscallnumNtOpenFile == candNtQueryInformationFile) || (syscallnumNtClose == candNtQueryInformationFile))
//			continue;	///Skip the ones we already know...

//		ioSb.Pointer = NULL;
//		RtlSecureZeroMemory(&ntdllInfo, sizeof(FILE_STANDARD_INFORMATION));
//		//myWPrintf(&lineNum, L"candNtQueryInformationFile: 0x%lX", candNtQueryInformationFile);
//		status = syscallStub(candNtQueryInformationFile, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
//		if (status)
//			continue;

//		if ((NTDLL_MIN_SIZE < ntdllInfo.EndOfFile.QuadPart) &&
//			(ntdllInfo.EndOfFile.QuadPart <= ntdllInfo.AllocationSize.QuadPart) &&
//			(ntdllInfo.AllocationSize.QuadPart <= NTDLL_MAX_SIZE)) {

//			///The retrieved ntdll.dll size is reasonable, we are likely to have figured
//			///out the NtOpenFile system call correctly.
//			ntdllSize = ntdllInfo.EndOfFile.QuadPart;
//			if (ntdllBufferSize < ntdllSize)
//				return STATUS_BUFFER_TOO_SMALL;
//			myWPrintf(&lineNum, L"ntdllSize: 0x%llX", ntdllSize);
//			break;
//		}
//	}

//	if (!ntdllSize)		///NtClose might have been worked but NtQueryInformationFile did not? Then try next syscall number
//		continue;		///since it seems, we still have a problem with the NtOpenFile number.

//}

//if (NT_INVALID_SYSCALL == syscallnumNtOpenFile)	///This means we could not even open the file. Maybe AV/HIPS prevents even read access
//	return STATUS_ORDINAL_NOT_FOUND;			///to the ntdll.dll DLL?

//myWPrintf(&lineNum, L"syscallnumNtQueryInformationFile = %lX", syscallnumNtQueryInformationFile);
//syscallStub(syscallnumNtClose, hFile);
//myWPrintf(&lineNum, L"agzsui %lX %lX", ioSb.Status, candNtReadFile);
//myWPrintf(&lineNum, L"Telltale \"MZ\" @ %p!", pFilledNtdllBuffer);
//RtlRv
////	status = syscallStub(j, hArbHandle, 0x3333333333333333, 0x3333333333333333, 0x3333333333333333);
////	myWPrintf(&lineNum, L"Completed API %lX with %lX status.", j, status);
////}
//
////NtSetIoCompletion(0x185, )
////syscallStub(0x185, hArbHandle, 0x3333333333333333, 0x3333333333333333, 0x3333333333333333);
////for (ULONG j = 0; j < 0x1000; j++) {
////	for (ULONGLONG i = 0; i < 0x200; i+=4) {
////		status = syscallStub(j, i, 0x3333333333333333, 0x3333333333333333, 0x3333333333333333);
////		if (!status) {
////			status = syscallStub(j, i, 0x3333333333333333, 0x3333333333333333, 0x3333333333333333);
////			if (STATUS_INVALID_HANDLE == status) {
////				myWPrintf(&lineNum, L"NtClose candidate: %lX", j);
////			}
////		}
////	}
////}
////goto go;
////for (ULONGLONG i = 0; i < 0x1000; i+=4)

////NtClose((HANDLE)1);



//	//		NtClose((HANDLE)i);
//	//NtWaitForSingleObject(i, );
////NtAlertResumeThread;
////NtAlertThread;
////NtSetLowWaitHighThread

////HANDLE hFile = (HANDLE)0x46786997B9689671;
////syscallStub(0xE5, &hFile);

////myWPrintf(&lineNum, L"%lX", hFile);


//
////NtSuspendProcess(INVALID_HANDLE_VALUE);
//	NtTerminateProcess(INVALID_HANDLE_VALUE, STATUS_SUCCESS);
//		myWPrintf(&lineNum, L"Found NtOpenFile syscall 0x%lX", i);
//		ntCreateFileNum = i;
//		break;
//	}
//}

//for (ULONG i = 0; i < 500; i++) {
//	status = syscallStub(i, hFile);
//	if (!status) {
//		status = syscallStub(i, hFile);
//		if (STATUS_INVALID_HANDLE == status) {
//			myWPrintf(&lineNum, L"Found NtClose syscall 0x%lX", i);
//			ntCloseNum = i;
//			break;
//		}
//	}
//}
//
//hFile = (HANDLE)0xC0FFEEBABE;
//status = syscallStub(ntCreateFileNum, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//if ((!status) && hFile && ((HANDLE)0xC0FFEEBABE != hFile) && (INVALID_HANDLE_VALUE != hFile)) {
//	myWPrintf(&lineNum, L"Found NtOpenFile syscall 0x%lX", ntCreateFileNum);
//}
//


////NtSetInformationObject(hFile)
//FILE_STANDARD_INFORMATION ntdllInfo;
//RtlSecureZeroMemory(&ntdllInfo, sizeof(FILE_STANDARD_INFORMATION));
//for (ULONG i = 0; i < 500; i++) {
//	if (ntCloseNum == i)
//		continue;

//	status = syscallStub(i, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
//	if ((!status) && (0 != ntdllInfo.EndOfFile.QuadPart) && (0x200000 > ntdllInfo.EndOfFile.QuadPart)) {
//		myWPrintf(&lineNum, L"Found NtQueryInformationFile syscall 0x%lX", i);
//		break;
//	}
//}

//myWPrintf(&lineNum, L"size of ntdll: %llX, 0x%llX", ntdllInfo.EndOfFile.QuadPart, ntdllInfo.AllocationSize.QuadPart);
////PVOID pNtdllBase = NULL;
////ULONGLONG ntdllSize = ntdllInfo.AllocationSize.QuadPart;
////NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pNtdllBase, 0, &ntdllSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

//for (ULONG i = 0; i < 500; i++) {
//	if ((ntCloseNum == i) || (ntCreateFileNum == i))
//		continue;

//	status = syscallStub(i, hFile, NULL, NULL, NULL, &ioSb, pNtdll, (ULONG)ntdllInfo.EndOfFile.QuadPart, NULL, NULL);
//	if (!status) {
//		if (((PIMAGE_DOS_HEADER)pNtdll)->e_magic == IMAGE_DOS_SIGNATURE)
//			break;
//	}
//}

//syscallStub(ntCloseNum, hFile);
//myWPrintf(&lineNum, L"All set up successfully! Pristine ntdll located @ %p", pNtdll);
////status = NtReadFile(hFile, NULL, NULL, NULL, &ioSb, pNtdll, (ULONG)ntdllInfo.EndOfFile.QuadPart, NULL, NULL);
////if (status) 
////	myWPrintf(&lineNum, L"NtReadFile: 0x%lX", status);
////	
////myWPrintf(&lineNum, L"%s", pNtdll);
//////myWPrintf(&lineNum, L"ntdll")
////	//if (!syscallStub(0x11, hFile, &ioSb, &ntdllFileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation));

//////if (!syscallStub(i, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT))
////	//	break;

//
////NtCreateSection;
////NtMapViewOfSection;
////FILE_BASIC_INFORMATION fileInfo;
////FILE_STANDARD_INFORMATION ntdllFileInfo;
////RtlSecureZeroMemory(&ntdllFileInfo, sizeof(FILE_STANDARD_INFORMATION));
//////NtQueryInformationFile
////for (ULONG i = 0; i < 500; i++)
////	if(!syscallStub(0x11, hFile, &ioSb, &ntdllFileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation));

////myWPrintf(&lineNum, L"size of ntdll: %llX", ntdllFileInfo.EndOfFile.QuadPart);
////



//////	syscallStub(i, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//////status = NtQueryInformationFile(hFile, &ioSb, &ntdllFileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

////if (status) {
////	DebugPrintA("Could not query ntdll.dll size, 0x%lX", status);
////	return status;
////}

////regionSize = ntdllFileInfo.EndOfFile.QuadPart;
////DebugPrintA("About to allocate %ld kilo bytes of memory!", regionSize / 1024);
////status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, ppBaseAddress, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
////if (status) {
////	DebugPrintA("Could allocate ntdll.dll info, 0x%lX", status);
////	return status;
////}
////NtQueryAttributesFile(&fileAttr, &fileInfo);
////NtQueryInformationFile()
////myWPrintf(&lineNum, L"bleh, %llX", fileInfo.)
////for (ULONG i = 0; i < 500; i++)
////	syscallStub(i, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);

////status = g_fpNtRaiseHardError(0xC0000007, 1, 1, a, 3, (PULONG)&status);
////((PULONG)(syscallStub))[3] = 0x55;
//LARGE_INTEGER interval;
//interval.QuadPart = -5000000;
////syscallStub(0x55, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
//syscallStub(0x34, FALSE, &interval);
//syscallStub(0x19F, INVALID_HANDLE_VALUE);
////NtCreateFile(&hFile, MAXIMUM_ALLOWED, &fileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
////NtCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
////status = NtRaiseHardError(0x80000007, 0, 0, NULL, 0, (PULONG)&status);
////g_fpNtRaiseHardError(0xAFFE, 0x1337, 0x4444, 0xDEAD, 0xCAFE, 0xC0FFEE, 0xBAADF00D, 0xC0FFEEBABE);
////syscallStub(243, 0xAFFE, 0x1337, 0x4444, 0xDEAD, 0xCAFE, 0xC0FFEE, 0xBAADF00D, 0xC0FFEEBABE);
//myWPrintf(&lineNum, L"zuasdzic%pdzdc      0 %lX", &lineNum, status);
//for (ULONG i = 0; i < NT_SYSCALL_END; i++)
//	syscallStub(i, INVALID_HANDLE_VALUE);
//}

//				for (ULONG candNtReadFile = NT_SYSCALL_START; candNtReadFile < NT_SYSCALL_END; candNtReadFile++) {
//					status = syscallStub(candNtReadFile, hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, (ULONG)ntdllInfo.EndOfFile.QuadPart, NULL, NULL);
//					if (status)
//						continue;


//		//	status = syscallStub(candNtOpenFile, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//		//	if()
//		//}

//		syscallnumNtOpenFile = candNtOpenFile;

//		
//		///Since the NtClose call might appear before our actual NtQueryInformationFile call
//		///there are three possible outcomes of the next check:
//		///==> The NtQueryInformationFile number is smaller than the NtClose number and the related call
//		///provides us with a valid ntdll.dll file size.
//		///==> The NtClose call succeeds and closes our handle. After that the handle value is still valid
//		///but the handle cannot be used any longer. If we try to call NtClose the 2nd time it must not succeed
//		///and we can once more call NtOpenFile to receive a valid file handle.
//		///==> Neither NtQueryInformationFile nor NtClose succeeds, so we have a major issue with our handle.
//		///It might be a fake NtOpenFile then, so we continue looping over system call numbers.
//		for (ULONG candNtQueryInformationFileOrNtClose = NT_SYSCALL_START; candNtQueryInformationFileOrNtClose < NT_SYSCALL_END; candNtQueryInformationFileOrNtClose++) {
//			RtlSecureZeroMemory(&ntdllInfo, sizeof(FILE_STANDARD_INFORMATION));
//			status = syscallStub(candNtQueryInformationFileOrNtClose, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
//			if (status)
//				continue;
//			
//			if((NTDLL_MIN_SIZE < ntdllInfo.EndOfFile.QuadPart) &&
//				(ntdllInfo.EndOfFile.QuadPart <= ntdllInfo.AllocationSize.QuadPart) &&
//				(ntdllInfo.AllocationSize.QuadPart <= NTDLL_MAX_SIZE)){
//				///The retrieved ntdll.dll size is reasonable, now attempt to read the file into caller-allocated buffer.


//				if (status)
//					return status;
//					
//					, ntdllInfo.EndOfFile)
//				j--;
//				continue;
//			}
//				if (((PIMAGE_DOS_HEADER)pNtdll)->e_magic == IMAGE_DOS_SIGNATURE)
//					break;
//			}

//		status = syscallStub(candNtQueryInformationFileOrNtClose, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

//	if (status)
//		continue;
//			status = syscallStub(i, hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, (ULONG)ntdllInfo.EndOfFile.QuadPart, NULL, NULL);
//			syscallStub(i, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//		}

//		///Sinc///has the correct access or if it  the handle to perform the wanted actionsvalue seems to be validThe handle value seems to be valid.
//		if((hFile) && (!((ULONGLONG)hFile % 4)))


//		hFile &&	///A valid file handle must have a value > 0.

//	///We know, if

//		(!((ULONGLONG)hFile % 4)))	///A valid file handle must be divisible by 4.

//		myWPrintf(&lineNum, L"Found NtOpenFile syscall 0x%lX", i);
//		ntCreateFileNum = i;
//		break;
//	}
//}
////syscallStub(0x1D, &hFile, KEY_READ, &keyAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
////syscallStub(0x10C, &hFile, KEY_READ, &keyAttr, REG_OPTION_NON_VOLATILE);
////NtOpenKeyEx

//hFile = (HANDLE)0xC0FFEEBABE;
////status = syscallStub(0x14D, 0xC0000007, 1, 1, a, 3, (PULONG)&status);
////NtCreateKey()
//ULONG ntCreateFileNum = 0;
//ULONG ntCloseNum = 0;

//for (ULONG i = 0; i < 500; i++) {
//	status = syscallStub(i, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//	if ((!status) && hFile && ((HANDLE)0xC0FFEEBABE != hFile) && (INVALID_HANDLE_VALUE != hFile)) {
//		myWPrintf(&lineNum, L"Found NtOpenFile syscall 0x%lX", i);
//		ntCreateFileNum = i;
//		break;
//	}
//}
//}

//myWPrintf(&lineNum, L"file related status: %lX %lX", ioSb.Status, candNtOpenFile);

//switch (status) {
//case STATUS_OBJECT_NAME_INVALID: {

//}
//}
//if (STATUS_OBJECT_PATH_NOT_FOUND == status) 
//	myWPrintf(&lineNum, L"0xC000003A @ API num %lX", candNtOpenFile);

//myWPrintf(&lineNum, L"Unhandled exception with %lX!", candNtOpenFile);
//if (STATUS_OBJECT_NAME_INVALID == status) {
//	myWPrintf(&lineNum, L"0xC0000033 @ API num %lX", candNtOpenFile);
//	//return status;
//}
//		hFile = hTestHandle;
//		ioSb.Pointer = NULL;
//		RtlInitUnicodeString(&uNtdll, L"\\systemroot\\system32\\ntdll.dll");
//		InitializeObjectAttributes(&fileAttr, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
//		status = syscallStub(candNtOpenFile, &hFile, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
//		if (status)
//HANDLE hFile = (HANDLE)0xDBBDBBDBBDBDBCDC;
//ULONG syscallnumCandidateNtClose = 0x0;
//ULONG syscallnumCandidateNtCreateFile = 0x0;
//HANDLE hFile;
//PVOID pFuncArray[0x100];

//typedef NTSTATUS(*PMYP_SYSCALL)(ULONG syscallNum, ...);
//PMYP_SYSCALL syscallStub;
//extern NTSTATUS mytest(ULONGLONG param1);
//extern NTSTATUS mySyscall(ULONG syscallNum, ...);

//NTSTATUS KiUserExceptionDispatcher(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG, ...);
//NTSTATUS KiUserInvertedFunctionTable(ULONGLONG blah, ...);
//NTSTATUS KiUserCallbackDispatcher(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG, ...);
//NTSTATUS customCallKiUserCallbackDispatcher(ULONGLONG, ULONGLONG, ULONGLONG);
//NTSTATUS KiUserInvertedFunctionTable
//NTSTATUS mySyscall(ULONGLONG syscallNr, ...) {
//	va_list args;
//
//	NTSTATUS status = STATUS_UNSUCCESSFUL;
//
//	va_start(args, syscallNr);
//	status = syscallStub((ULONGLONG)args);
//	va_end(args);
//	return status;

//}
//void myDispatch(void) {
//	USHORT lineNum;
//	LARGE_INTEGER interval;
//	interval.QuadPart = -10000000;
//	myWPrintf(&lineNum, L"HelloWorld from dispatcher%p!", KiUserInvertedFunctionTable);
//
//	PUCHAR ptr = NULL;
//	NtDelayExecution(FALSE, &interval);
//	syscallStub(4096, 0xC0FF33BABE, 0xC0FFEEAFFE, 0x1337C00C1E, 0xEEEEEEEBCDD3, 0xFFFFFF897FFF8711);
//	__try{
//		*ptr = 67;
//		//KiUserCallbackDispatcher(0, 0, 0, 0, 0x548, 0x3464);
//	}
//	__except(EXCEPTION_EXECUTE_HANDLER){
//		myWPrintf(&lineNum, L"Exception dispatch!");
//		NtCallbackReturn(NtCurrentPeb(), 0x80, STATUS_SUCCESS + 1);
//		syscallStub(4367, 0xC0FF33BABE, 0xC0FFEEAFFE, 0x1337C00C1E, 0xEEEEEEEBCDD3, 0xFFFFFF897FFF8711);
//		KiUserExceptionDispatcher(645, 796896, 768678707, 767858568585, 7777585575897589, 6768656876586887658);
//	}
//	syscallStub(4367, 0xC0FF33BABE, 0xC0FFEEAFFE, 0x1337C00C1E, 0xEEEEEEEBCDD3, 0xFFFFFF897FFF8711);
//}
//HANDLE hFile = (HANDLE)0xDBBDBBDBBDBDBCDD;
//UNICODE_STRING uKey;
//RtlInitUnicodeString(&uKey, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
//			return status;	///We succeeded the first time but failed at the second attempt? Strange. We have a major problem. 

//		syscallnumNtClose = candNtClose;	///Save the found NtClose number in order to:
//											///==> Safely skip it in the following NtQueryInformationFile and NtReadFile number scans
//											///==> Be able to close the file if not needed anymore.
//		break;
//	}
//}



//a[0] = (ULONGLONG)&uNtdll;

//RtlMoveMemory(syscallStub, pShellcode, sizeof(pShellcode));
//g_fpNtRaiseHardError = (PNT_RAISE_HARD_ERROR)((ULONGLONG)syscallStub + 0x800);
//RtlMoveMemory(g_fpNtRaiseHardError, pNtRaiseHardError, sizeof(pNtRaiseHardError));
//NtSuspendProcess(INVALID_HANDLE_VALUE);
//OBJECT_ATTRIBUTES keyAttr;
//InitializeObjectAttributes(&keyAttr, &uKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
//DbgBreakPoint();
//NtCreateFile(0x55, &hFile, MAXIMUM_ALLOWED, &fileAttr, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
//status = syscallStub(23, 45,25,26);
//status = syscallStub(0x55, )
//NtQueryObject();
//OBJECT_BASIC_INFORMATION obj;
//OBJECT_TYPE_INFORMATION obj2; ObjectTypeInformation;
//if (STATUS_OBJECT_NAME_NOT_FOUND == status) {
//	myWPrintf(&lineNum, L"0xC0000034 @ API num %lX", candNtOpenFile);
//	//return status;
//}

//if (STATUS_OBJECT_PATH_SYNTAX_BAD == status) {
//	myWPrintf(&lineNum, L"0xC000003B @ API num %lX", candNtOpenFile);
//	//return status;
//}

//if (STATUS_OBJECT_PATH_INVALID == status) {
//	myWPrintf(&lineNum, L"0xC0000039 @ API num %lX", candNtOpenFile);
//	//return status;
//}



//if (STATUS_SHARING_VIOLATION == status) {
//	myWPrintf(&lineNum, L"0xC0000043 @ API num %lX", candNtOpenFile);
//	//return status;
//}


//typedef struct _API_INFO {
//	ULONG syscallNum;
//	ULONG apiRva;
//}API_INFO, *PAPI_INFO;
//
//typedef struct _NTAPI_ENTRY {
//	//API_INFO apiInfo;
//	ULONG syscallNum;
//	ULONG apiRva;
//} NTAPI_ENTRY, *PNTAPI_ENTRY;
//
//static char* sg_pszApiNames[] = {
//	"NtTerminateProcess",
//	"NtDelayExecution",
//	"NtWriteVirtualMemory",
//	"NtCreateUserProcess",
//	"NtOpenProcess",
//	"NtProtectVirtualMemory",
//	"NtWaitForWorkViaWorkerFactory",
//	"NtReadVirtualMemory",
//	"KiUserExceptionDispatcher",
//	"KiUserInvertedFunctionTable",
//	"NtSuspendProcess",
//	"NtRaiseHardError",
//	"NtUnmapViewOfSection",
//	"NtQueryVirtualMemory",
//	"NtOpenFile",
//	"NtCreateSection",
//	"NtMapViewOfSection",
//};
//
//typedef enum _API_NAMES {
//	ntTerminateProcess,
//	ntDelayExecution,
//	ntWriteVirtualMemory,
//	ntCreateUserProcess,
//	ntOpenProcess,
//	ntProtectVirtualMemory,
//	ntWaitForWorkViaWorkerFactory,
//	ntReadVirtualMemory,
//	kiUserExceptionDispatcher,
//	kiUserInvertedFunctionTable,
//	ntSuspendProcess,
//	ntRaiseHardError,
//	ntUnmapViewOfSection,
//	ntQueryVirtualMemory,
//	ntOpenFile,
//	ntCreateSection,
//	ntMapViewOfSection
//}API_NAMES, *PAPI_NAMES;
//
//NTAPI_ENTRY g_ntapiList[sizeof(sg_pszApiNames) / sizeof(char*)];
//typedef struct _NTAPI_FUNCTION_LIST {
//	NTAPI_ENTRY apiEntry[10];
//	//NTAPI_ENTRY ntTerminateProcess;
//	//NTAPI_ENTRY ntDelayExecution;
//	//NTAPI_ENTRY ntWriteVirtualMemory;
//	//NTAPI_ENTRY ntCreateUserProcess;
//	//NTAPI_ENTRY ntOpenProcess;
//	//NTAPI_ENTRY ntProtectVirtualMemory;
//	//NTAPI_ENTRY ntReadVirtualMemory;
//	//NTAPI_ENTRY ntWaitForWorkViaWorkerFactory;
//	//NTAPI_ENTRY kiUserExceptionDispatcher;
//	//NTAPI_ENTRY kiUserInvertedFunctionTable;
//} NTAPI_FUNCTION_LIST, *PNTAPI_FUNCTION_LIST;



//typedef struct _NTAPI_FUNCTION_LIST {
//	NTAPI_ENTRY ntTerminateProcess;
//	NTAPI_ENTRY ntDelayExecution;
//	NTAPI_ENTRY ntWriteVirtualMemory;
//	NTAPI_ENTRY ntCreateUserProcess;
//	NTAPI_ENTRY ntOpenProcess;
//	NTAPI_ENTRY ntProtectVirtualMemory;
//	NTAPI_ENTRY ntReadVirtualMemory;
//	NTAPI_ENTRY ntWaitForWorkViaWorkerFactory;
//	NTAPI_ENTRY kiUserExceptionDispatcher;
//	NTAPI_ENTRY kiUserInvertedFunctionTable;
//} NTAPI_FUNCTION_LIST, *PNTAPI_FUNCTION_LIST;
///We now attempt to query the file size. If we checked 
//for (ULONG candNtQueryInformationFile = NT_SYSCALL_START; candNtQueryInformationFile < NT_SYSCALL_END; candNtQueryInformationFile++) {
//	if ((syscallnumNtClose == candNtQueryInformationFile))
//		continue;	///Skip the ones we already know...

//	ioSb.Status = 0x13371337;
//	RtlSecureZeroMemory(&ntdllInfo, sizeof(FILE_STANDARD_INFORMATION));

////	__try {
//		status = syscallStub(candNtQueryInformationFile, hFile, &ioSb, &ntdllInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
//	//}
//	//__except (EXCEPTION_EXECUTE_HANDLER){
//	//	return STATUS_UNHANDLED_EXCEPTION;
//	//}

//	if (0x13371337 == ioSb.Status)	///This test has an extremely strong filtering behavior!
//		continue;

//	if (status)
//		continue;

//	if ((NTDLL_MIN_SIZE < ntdllInfo.EndOfFile.QuadPart) &&
//		(ntdllInfo.EndOfFile.QuadPart <= ntdllInfo.AllocationSize.QuadPart) &&
//		(ntdllInfo.AllocationSize.QuadPart <= NTDLL_MAX_SIZE)) {
//		*pDebugBuffer = 4;
//		///The retrieved ntdll.dll size is reasonable, we are likely to have figured
//		///out the NtOpenFile system call correctly.
//		ntdllSize = ntdllInfo.EndOfFile.QuadPart;
//		if (ntdllBufferSize < ntdllSize)
//			return STATUS_BUFFER_TOO_SMALL;

//		syscallnumNtOpenFile = candNtOpenFile;
//		syscallnumNtQueryInformationFile = candNtQueryInformationFile;
//		break;
//	}
//}

//if (ntdllSize)		///NtClose might have been worked but NtQueryInformationFile did not? Then try next syscall number
//	break;		///since it seems, we still have a problem with the NtOpenFile number.

//status = NtReadFile(hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, (ULONG)ntdllBufferSize, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//if (status) {
//status = syscallStub(0x1B3, &status, 0, 0x9999999999999999);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
////	return status;
////}
////NtOpenEvent()
//status = NtReadFile(hFile, (HANDLE)4, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//status = NtReadFile(hFile, (HANDLE)8, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//	//pFirstSecHdr->Misc.VirtualSize
//
//	////__movsb(pCurrName, pNameOrdinalArray, 67);
//
//	////myWPrintf(&lineNum, L"pFileOffset = %llX", stringLen);
//	//if (RtlEqualMemory(pCurrName, "NtSuspendProcess", sizeof("NtSuspendProcess") - sizeof(ANSI_NULL))) {
//	//	currFunctionRva = pFunctionRvaArray[pNameOrdinalArray[i]];
//	//	pDesiredFunc = rvaToFileOffset(currFunctionRva, pFilledNtdllBuffer);
//	//	myWPrintf(&lineNum, L"pFileOffset = %p", pDesiredFunc);
//ntapiInfo.apiRva = rvaCurrentFunction;
//if (NT_INVALID_SYSCALL > ((PNT_SYSCALL_STUB)pDesiredFunctionAddress)->syscallNumber)

//if (!strcmp(pCurrName, pNtOrZwXxxApiName)/*RtlEqualMemory(pCurrName, pNtOrZwXxxApiName, apiNameLen)*/) {
//strcpy(sg_pSyscallTable, )
//memcpy(sg_pSyscallTable, pCurrName, )
//	ntapiInfo.syscallNum = ((PNT_SYSCALL_STUB)pDesiredFunctionAddress)->syscallNumber;

//break;
//	//	syscallStub(((PULONG)pDesiredFunc)[1], INVALID_HANDLE_VALUE);
//	//	//return (LONG);
//	//}
//
//	//RtlCompareMemory()
//
//
//	//RtlEqualString()
//	//myWPrintf(&lineNum, L"%s", ;
//	//myWPrintf(&lineNum, L"oaduhiadusi%lX", pNtdllDataDir->VirtualAddress);
//	//pExportDir = (PIMAGE_EXPORT_DIRECTORY)rvaToFileOffset(pNtdllDataDir->VirtualAddress, pFilledNtdllBuffer);
//
//	//myWPrintf(&lineNum, L"Number0fFuncs: %d", pExportDir->NumberOfFunctions);
//
//	//PULONG pAddressOfNames = (PULONG)(pExportDirectory->AddressOfNames + pBaseAddress - rdataBias);
//	//PUSHORT pAddressOfNameOrdinals = (PUSHORT)(pExportDirectory->AddressOfNameOrdinals + pBaseAddress - rdataBias);
//	//PULONG pAddressOfFunctions = (PULONG)(pExportDirectory->AddressOfFunctions + pBaseAddress - rdataBias);
//	//RtlUnicodeStringInit;
//
//	ULONG currNameRva = 0;
//	ULONG currFunctionRva = 0;
//	SIZE_T stringLen = 0;
//	PVOID pDesiredFunc = NULL;
//	PULONG pNameRvaArray = (PULONG)rvaToFileOffset(pExportDir->AddressOfNames, pFilledNtdllBuffer);
//	PUSHORT pNameOrdinalArray = (PUSHORT)rvaToFileOffset(pExportDir->AddressOfNameOrdinals, pFilledNtdllBuffer);
//	PULONG pFunctionRvaArray = (PULONG)rvaToFileOffset(pExportDir->AddressOfFunctions, pFilledNtdllBuffer);
//	char* pCurrName = NULL;
//	USHORT currOrdinal = 0;
//
//
//	//tlStringCbLengthA
//	//while (i < pExportDir->NumberOfNames) {
//	//	currNameRva = pAddressOfNames[i];
//	//	currOrdinal = pAddressOfNameOrdinals[i];
//	//	pCurrName = currNameRva + pBaseAddress - rdataBias;
//
//	//	if (!strncmp((LPCSTR)pCurrName, pDesiredFunction, NameLength)) {
//	//		currFunctionRva = pAddressOfFunctions[currOrdinal];
//	//		functionAddress = (ULONGLONG)(currFunctionRva + pBaseAddress - textBias);
//	//		return functionAddress;
//	//	}
//	//	i++;
//	//}
//	//functionAddress = 0x0;
//	//return functionAddress;
//	//pExportDir->Name
//	////*ppExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDataDirectory->VirtualAddress + *ppBaseAddress - *pRdataBias);
//	//NtRaiseHardError(0, 0, 0, NULL, 0, (PULONG)&status);
//
//	//pNameRvaArray = (PULONG)((PUCHAR)pImageFileBase + pExportDirectory->AddressOfNames);
//	//maxReadSize = pExportDirectory->NumberOfNames * sizeof(ULONG);
//	//status = validatePePointer(pImageFileBase, pNameRvaArray, maxReadSize, FALSE);
//	//if (status)
//	//	return status;
//
//	/////Since NumberOfNames can be any value, we need to roughly estimate the exportSize
//	/////according to the combined sizes of the three export describing arrays.
//	/////If this yields to greater export size than the claimed export size, the image must be rejected.
//	//minExportSize = sizeof(ULONG) * pExportDirectory->NumberOfFunctions + pExportDirectory->NumberOfNames * sizeof(ULONG) + sizeof(USHORT) + sizeof(ANSI_NULL);
//	//if (exportSize <= minExportSize)
//	//	return STATUS_INVALID_IMAGE_FORMAT;
//
//	/////It is NOT guaranteed, that an entry in the name RVA array at position 'n' has a value
//	/////which also orders as the n-th element in the entire name RVA range.
//	/////It is therefore not permissible to calculate the name length by simply doing
//	/////pNameRvaArray[n+1] - pNameRvaArray[n]. If we still want to make this assumption
//	/////the RVAs values must be sorted until they are in an ascending order.
//	/////By utilizing the last unused bytes of the caller-allocated buffer we avoid having
//	/////to allocate a buffer on our own. Doing the math above (see exportsize calculation)
//	/////one can prove that the safety margin is sufficient if we use the buffer in that way.
//	//piListBuffer = (PULONG)(pListBuffer + *pNeededBufferSize - pExportDirectory->NumberOfNames * sizeof(ULONG));
//	//RtlCopyMemory(piListBuffer, pNameRvaArray, pExportDirectory->NumberOfNames * sizeof(ULONG));
//	//qsort(piListBuffer, (ULONGLONG)pExportDirectory->NumberOfNames, sizeof(ULONG), mycompare);
//
//	/////Is it safe to read the module name?
//	//maxReadSize = pNameRvaArray[0] - pExportDirectory->Name;
//	//status = validatePePointer(pImageFileBase, (PVOID)((PUCHAR)pImageFileBase + pExportDirectory->Name), maxReadSize, FALSE);
//	//if (status)
//	//	return status;
//
//	//if (moduleNameSize < maxReadSize)
//	//	return STATUS_STACK_OVERFLOW;
//
//	//RtlCopyMemory(pModuleName, (PUCHAR)pImageFileBase + pExportDirectory->Name, maxReadSize);
//	//pModuleName[maxReadSize - 1] = 0x0;
//	//pListPointer = pListBuffer;
//	//printf_s("\nmodule name: %s", pModuleName);
//
//	//pNameRvaArray = piListBuffer;
//	//for (ULONG i = 0; i < pExportDirectory->NumberOfNames; i++) {
//	//	///Will none of the obtained name RVAs evaluate to an invalid name pointer?
//	//	if (!(exportSize + pDataDirectory->VirtualAddress > pNameRvaArray[i]))
//	//		return STATUS_INVALID_IMAGE_FORMAT;
//
//	//	pCurrName = (PUCHAR)pImageFileBase + pNameRvaArray[i];
//	//	///At the end of RVA array there is no longer a next name entry.
//	//	///There must by PE design a terminating zero though, which we're going to exploit
//	//	///in order to still have a valid name length.
//	//	if (pExportDirectory->NumberOfNames - 1 == i) {
//	//		int j = 0;
//	//		while (pCurrName[j])
//	//			j++;
//
//	//		nameLength = j;
//	//	}
//	//	else {
//	//		nameLength = (ULONGLONG)(pNameRvaArray[i + 1] - pNameRvaArray[i]/*pNextName - pCurrName*/) - 1;
//	//	}
//	//	///If for some reason the allocated buffer is about to be overran
//	//	///we print an error signature into the buffer and abort the scan.
//	//	///In regard of our thousands of sanity checks this surely denotes a major PE damage.
//	//	///Additionally, we break a little earlier to not have the failure overwrite the sorted RVAs.
//	//	if ((PUCHAR)piListBuffer <= pListPointer + nameLength + sizeof(WCHAR)) {
//	//		pCurrName = szError;
//	//		nameLength = sizeof(szError) - 1;
//	//		pListPointer = (PUCHAR)piListBuffer - (nameLength + sizeof(WCHAR));
//	//		///Indirect break, bail out.
//	//		i = pExportDirectory->NumberOfNames;
//	//	}
//
//	//	RtlCopyMemory(pListPointer, pCurrName, nameLength);
//	//	*(PWCHAR)&pListPointer[nameLength] = (WCHAR)0x0A0D;
//	//	pListPointer += nameLength + sizeof(WCHAR);
//	//}
//	//	pNtdllDataDir->VirtualAddress;
//	//	
//	//	pFirstSecHdr->Misc.
//	//	__C_specific_handler;
//	//	foundRdata = TRUE;
//	//	DebugPrintA("Found .rdata section, now calculating rdata bias!");
//	//
//	//	*pRdataBias = currSecHdr.VirtualAddress - currSecHdr.PointerToRawData;
//	//}
//	//	}
//	//
//	//	if (!foundText || !foundRdata) {
//	//		DebugPrintA("Fatal Error! Could not get one or both virtual-to-realaddress biases!");
//	//		return STATUS_INVALID_IMAGE_FORMAT;
//	//	}
//	//
//	//	DebugPrintA("rdataBias: 0x%llx, textBias: 0x%llX", *pRdataBias, *pTextBias);
//	//
//	//	DebugPrintA("Data Directory Begin: 0x%llx", (ULONGLONG)pDataDirectory);
//	//
//	//	*ppExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDataDirectory->VirtualAddress + *ppBaseAddress - *pRdataBias);
//	//	DebugPrintA("Export Directory Size: 0x%lx", (ULONG)pDataDirectory->Size);
//	//	DebugPrintA("Data Directory RVA: 0x%lx", (ULONGLONG)(pDataDirectory->VirtualAddress));
//	//	DebugPrintA("Func Count: 0x%llx", (ULONGLONG)(*ppExportDirectory));
//	//
//	//	return STATUS_SUCCESS;
//	//	//if (1 > pHdr64->OptionalHeader.NumberOfRvaAndSizes) {
//	//	//	DebugPrintA("Image doesn't have export directory!");
//	//	//	return 0x0;
//	//	//}
//	//	//PIMAGE_DATA_DIRECTORY pDataDirectory = &pHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
//	//	//PIMAGE_SECTION_HEADER pFirstSecHdr = IMAGE_FIRST_SECTION(pHdr64);
//	return STATUS_SUCCESS;
//}
//mystrlen PROC
//xor rax, rax
//looop :
//inc rax
//inc rcx
//cmp byte ptr[rcx], 0
//jne looop
//ret
//
//push rdi
//mov rdi, rcx
//or rcx, -1
//xor eax, eax
//cld
//repne scasb
//not rcx
//dec	rcx
//mov rax, rcx
//pop rdi
//ret
//mystrlen ENDP


//status = NtReadFile(hFile, (HANDLE)12, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//status = NtReadFile(hFile, (HANDLE)16, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//status = NtReadFile(hFile, (HANDLE)20, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//status = NtReadFile(hFile, (HANDLE)24, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//status = NtReadFile(hFile, (HANDLE)28, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
//NtRaiseHardError(status-3, 0, 0, NULL, 0, (PULONG)&status);


//if (NT_INVALID_SYSCALL == syscallnumNtOpenFile){
//	*pDebugBuffer = 5;///This means we could not even open the file. Maybe AV/HIPS prevents even read access
//	return STATUS_ORDINAL_NOT_FOUND;			///to the ntdll.dll DLL?
//}



/////If we made it till here we strongly assume that we have found not only the correct NtOpenFile but also the correct
/////NtClose and NtQueryInformationFile number. We now have pretty good chances of succeeding upon attemping to read the
/////ntdll.dll file into memory.
////for (ULONG candNtReadFile = NT_SYSCALL_START; candNtReadFile < NT_SYSCALL_END; candNtReadFile++) {
////	if ((syscallnumNtOpenFile == candNtReadFile) ||
////		(syscallnumNtClose == candNtReadFile) ||
////syscallStub(syscallnumNtClose, hFile);
////NtCreateSection
////status = NtRead
////if (0x1B0 == candNtReadFile)
////NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);

////return STATUS_SUCCESS;
////continue;
////NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
////	return STATUS_INVALID_IMAGE_FORMAT;
////return STATUS_INVALID_IMAGE_WIN_32;
////return STATUS_INVALID_IMAGE_FORMAT;
////{
////status = STATUS_SUCCESS;
////if (0x1B0 == candNtReadFile)
////if (0x1B3 == candNtReadFile)
////	continue;
////if ((syscallnumNtOpenFile == candNtReadFile) ||
////	(syscallnumNtClose == candNtReadFile) ||
////	(syscallnumNtQueryInformationFile == candNtReadFile))
////	NtRaiseHardError(0x40000009, 0, 0, NULL, 0, (PULONG)&status);
////status = NtReadFile(hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
////*pDebugBuffer = (ULONG)ntdllSize;
////break;
////}
////NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
////if (IMAGE_DOS_SIGNATURE == *(PUSHORT)pNtdllBuffer) {
////	status = STATUS_SUCCESS;
////	*pDebugBuffer = (ULONG)ntdllSize;
////	break;
////}

////if ((NTDLL_MIN_SIZE < ioSb.Information) &&
////	(ioSb.Information <= ntdllBufferSize) &&
//////		(ntdllInfo.AllocationSize.QuadPart <= NTDLL_MAX_SIZE)) 
////USHORT lineNum = 0x

////STATUS_END_OF_FILE == status
////if ((STATUS_END_OF_FILE != status) &&
////	(STATUS_)
////	continue;


////return status;
////		(syscallnumNtQueryInformationFile == candNtReadFile))
////		continue;	///Skip the ones we already know...
////	
////	ioSb.Status = 0xF000000D;
////	status = syscallStub(candNtReadFile, hFile, NULL, NULL, NULL, &ioSb, pNtdllBuffer, (ULONG)ntdllSize, NULL, NULL);
////	if (0xF000000D == ioSb.Status)	///This test has an extremely strong filtering behavior!
////		continue;
////	
////	if (status)
////		continue;

////	*pDebugBuffer = 6;
////	if (IMAGE_DOS_SIGNATURE == *(PUSHORT)pNtdllBuffer) {
////		status = STATUS_SUCCESS;
////		*pDebugBuffer = (ULONG)ntdllSize;
////		break;
////	}
////}
////
////syscallStub(syscallnumNtClose, hFile);
////return status;
//return STATUS_UNKNOWN_REVISION;

//SIZE_T mystrlen(const char* pString) {
//	SIZE_T stringLen = 0;
//	while (pString[stringLen])
//		stringLen++;
//	//}

//__except (EXCEPTION_EXECUTE_HANDLER) {
//	*pDebugBuffer = 2;
//myWPrintf(&lineNum, L"cizuv%lX", candNtOpenFile);
//__try {
//uNtdll.LengthInBytes = sizeof(L"\\systemroot\\system32\\ntdll.dll");
//uNtdll.MaximumLengthInBytes = sizeof(L"\\systemroot\\system32\\ntdll.dll") + sizeof(UNICODE_NULL);
///Since we now closed the handle we need to open the file again using the
///previously found NtOpenFile number. As mentioned above our pointer targets might have become destroyed.
///Just paranoidly renew everything.
//USHORT lineNum = 0;
//uNtdll.Buffer = L"\\systemroot\\system32\\ntdll.dll";
//RtlInitUnicodeString(&uNtdll, szFullNtdllName);
//RtlInitUnicodeString(&uNtdll, L"\\systemroot\\system32\\ntdll.dll");
//	return STATUS_UNHANDLED_EXCEPTION;
////}

//	return stringLen;
//}
//ntapiInfo.apiRva = 0x0;
//ntapiInfo.syscallNum = NT_INVALID_SYSCALL;



//for (ULONG i = 0; i < sizeof(g_ntapiList) / sizeof(NTAPI_ENTRY); i++)
//	g_ntapiList[i] = ntapiNameToNtapiInfo(sg_pszApiNames[i], pFilledNtdllBuffer);


//for (ULONG i = 0; i < sizeof(g_ntapiList) / sizeof(NTAPI_ENTRY); i++) {
//	g_ntapiList[i].pApiName = apiNames[i];

//if ((4 >((PIMAGE_DOS_HEADER)pFilledNtdllBuffer)->e_lfanew) ||
//	((PIMAGE_DOS_HEADER)pFilledNtdllBuffer)->e_lfanew >= (LONG)pBufferSize)
//	return STATUS_INVALID_IMAGE_FORMAT;

//	g_ntapiList[i].nameLength = 0;//(ULONG)strlen(apiNames[i]);
//}
//NtRaiseHardError(STATUS_NONEXISTENT_SECTOR, 0, 0, NULL, 0, (PULONG)&status);
//g_ntapiList[i].apiInfo = ntapiNameToNtapiInfo(g_ntapiList[i].pApiName, g_ntapiList[i].nameLength, pFilledNtdllBuffer);
//NtQueryInformationProcess();
//ProcessM

//for (ULONG i = 0; i <)
//pNtdllPeHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)pFilledNtdllBuffer + ((PIMAGE_DOS_HEADER)pFilledNtdllBuffer)->e_lfanew);
//if ((pNtdllPeHdr->Signature != IMAGE_NT_SIGNATURE) ||
//	(pNtdllPeHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
//	(pNtdllPeHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
//	return STATUS_INVALID_IMAGE_WIN_32;

//if (!pNtdllPeHdr->OptionalHeader.NumberOfRvaAndSizes)
//	return STATUS_INVALID_IMAGE_FORMAT;

//NTSTATUS performCoreInitialization(PVOID pNtdllBuffer, PULONG pDebugBuffer, PULONG pFirstOccurenceApi) {
//	UNICODE_STRING uNtdll;
//	OBJECT_ATTRIBUTES fileAttr;
//	IO_STATUS_BLOCK ioSb;
//	CONTEXT dummyCtx;
//	//FILE_STANDARD_INFORMATION ntdllInfo;
//
//	NTSTATUS status = STATUS_UNSUCCESSFUL;
//	HANDLE hArbObject = NULL;
//	ULONG syscallnumNtClose = NT_INVALID_SYSCALL;
//	//ULONG syscallnumNtOpenFile = NT_INVALID_SYSCALL;
//	//ULONG syscallnumNtQueryInformationFile = NT_INVALID_SYSCALL;
//	HANDLE hTestHandle = INVALID_HANDLE_VALUE;
//	HANDLE hFile = INVALID_HANDLE_VALUE;
//	WCHAR szFullNtdllName[] = L"\\systemroot\\system32\\ntdll.dll";
//	//ULONGLONG ntdllSize = 0;
//	PIMAGE_NT_HEADERS64 pNtdllPeHdr = NULL;
//
//	if (!pNtdllBuffer || !pDebugBuffer || !pFirstOccurenceApi)
//		return STATUS_INVALID_PARAMETER;
//
//	*pDebugBuffer = 0;
//	*pFirstOccurenceApi = 0;
//
//	///We will first try to find the NtClose syscall to prevent it from interfering with our other bruteforce attempts.
//	///E.g. If we were to find NtOpenFile and then tried to find NtReadFile but the NtClose call happened
//	///to appear before NtReadFile we would inadvertently close our handle and therefore use an invalid handle
//	///while attempting to find still unknown NtReadFile number and to read the file.
//	///We will exploit the fact that every process gets a few handles duplicated or inherited before even the
//	///very first instruction in the processes image. This might also be related to the usermode loader behavior.
//	///Since all these handles should be closable we just pick one after another and try to close them.
//	///A successful NtClose is defined as an operation which once succeeds using syscall number "n" and then fails
//	///with msdn-defined 0xC0000008 using both the very same syscall number and the same handle value.
//	HANDLE hCurrrDir = NtCurrentPeb()->ProcessParameters->CurrentDirectory.Handle;
//	for (ULONGLONG i = 4; i < 0x100; i++) {
//		hArbObject = (HANDLE)hCurrrDir;
//		for (ULONG candNtClose = NT_SYSCALL_START; candNtClose < NT_SYSCALL_END; candNtClose++) {
//			///Try to call NtClose on the handle the first time.
//			///Notice the bad aligned 64 bit values. These are to prevent NtWaitForXxx calls from working since not only
//			///does NtWaitForSingleObject have similar parameters but it also waits on a handle if the other parameters
//			///are specified with NULL/0. Clearly, our thread would be "stopped" if we ran into an NtWaitForXxx call
//			///while searching for NtClose. With the bad pointers it returns 0xC0000005 or 0x80000002 and does not wait. :) 
//			status = syscallStub(candNtClose, hArbObject, 0x1111111111111111, 0x3333333333333333, 0x7777777777777777);
//			if (STATUS_HANDLE_NOT_CLOSABLE == status) {	///We have found NtClose for sure but NtOpenFile provided us with a 
//				syscallnumNtClose = candNtClose;		///wrong (yet valid) handle value. We break the loop and note the NtClose
//				i = 0x100;								///number so the next time we don't have to scan for it again.
//				break;									
//			}
//
//			if (status)
//				continue;
//
//			///Did it succeed? Then call it the second time with the very same syscall number.
//			status = syscallStub(candNtClose, hArbObject, 0x1111111111111111, 0x3333333333333333, 0x7777777777777777);
//			if (STATUS_INVALID_HANDLE != status)	///If we now don't receive C0000008 (refer to msdn) we have not yet closed the handle
//				continue;							///and consequently not found NtClose. We'll try on.
//
//			syscallnumNtClose = candNtClose;
//			i = 0x100;
//			break;
//		}
//	}
//
//	///If we could not find NtClose we can't continue.
//	if (NT_INVALID_SYSCALL == syscallnumNtClose) {
//		*pDebugBuffer = 1;
//		return STATUS_ORDINAL_NOT_FOUND;
//	}
//
//	hTestHandle = (HANDLE)0xDBBDBBDBBDBDBCD1; ///This value is not divisibly by 4 without remainder. 
//	for (ULONG candNtOpenFile = NT_SYSCALL_START; candNtOpenFile < NT_SYSCALL_END; candNtOpenFile++) {
//		if (syscallnumNtClose == candNtOpenFile)
//			continue;
//
//		///If we start over the next iteration we just renew EVERYTHING. Since we can't expect the completely
//		///wrong called and failing routines to not alter our various pointer targets we need to be as paranoid
//		///as even possible and hence to everytime restart from scratch even if it costs more CPU time.
//		ioSb.Status = 0xBADBAAAD;
//		uNtdll.Buffer = szFullNtdllName;
//		uNtdll.LengthInBytes = sizeof(szFullNtdllName) - 2;
//		uNtdll.MaximumLengthInBytes = sizeof(szFullNtdllName);
//		InitializeObjectAttributes(&fileAttr, &uNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);
//		RtlSecureZeroMemory(&dummyCtx, sizeof(CONTEXT));
//
//		///Tests have shown that there is an NtContinue call which tries to execute invalid code in the own process when given
//		///simply a correct ContextFlags value of CONTEXT_AMD64 | 0x00000001. If we call NtOpenFile(&hFile) where hFile is
//		///located on the stack (by default) but in fact call NtContinue (since we don't know the syscall number yet!)
//		///the stack just needs to look like a CONTEXT structure with those ContextFlags set to any value which in case
//		///of an NtContinue call would include setting the RIP register. And we don't have too much knowledge and control of what
//		///happens to be on our stack especially, when calling completely random routines which can change the stack in various ways...
//		///For that reason we somewhat "define" what is located on our stack by allocating a real CONTEXT structure ourselves
//		///and initializing it with CONTEXT_AMD64 ContextFlags which does not set Rip register. That way, we can avoid
//		///"unauthorized" code execution.
//		///Luckily, the CONTEXT structure's first member is not ContextFlags but an unused value so we can easily initialize the
//		///first member with a bogus handle value and then let NtCreateFile deem it as an PHANDLE.
//		dummyCtx.ContextFlags = CONTEXT_AMD64;
//		dummyCtx.P1Home = (ULONGLONG)hTestHandle;
//		status = syscallStub(candNtOpenFile, &dummyCtx, GENERIC_READ | SYNCHRONIZE, &fileAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
//		hFile = (HANDLE)dummyCtx.P1Home;
//
//		///These are NTSTATUS values which are not likely with any other call than NtOpenFile or NtCreateFile.
//		///given the object path of \systemroot\system32 which cannot be e.g. a registry key... If we get one of these
//		///values we set a debug value so we know easier that we have a file problem in case of an error.
//		if (STATUS_OBJECT_NAME_INVALID == status ||
//			STATUS_OBJECT_NAME_NOT_FOUND == status ||
//			STATUS_OBJECT_PATH_INVALID == status ||
//			STATUS_OBJECT_PATH_NOT_FOUND == status ||
//			STATUS_OBJECT_PATH_SYNTAX_BAD == status) {
//			if (!*pFirstOccurenceApi) {
//				///Safe for later that we're likely to have a problem with our file name.
//				*pFirstOccurenceApi = candNtOpenFile;
//			}
//		}
//		
//		///This test has an extremely strong filtering behavior! Not only has the syscall recognized our buffer
//		///which is not the first or second parameter (like in NtGetXxx apis) but it has also written something in there.
//		///Only a few syscalls pass this test.
//		if (0xBADBAAAD == ioSb.Status)
//			continue;
//
//		if (status)		///Obviously, we expect nothing than STATUS_SUCCESS and since we attempted to open the file synchronously
//			continue;	///There cannot be returned a STATUS_PENDING.
//
//		///At this point, we successfully returned from the system call.
//		///First let us conduct some handle value analysis:
//		///We know that a valid file handle value must be evenly divisible by 4 and it must be greater than 0.
//		///This also implies that the handle value must have been changed (since above fake value is not divisible by 4!),
//		///so we can detect fake STATUS_SUCCESS returned by NtYieldExecution and continue the loop.
//		///It further implies, that the returned handle value cannot be magic number "INVALID_HANDLE_VALUE"
//		///as this isn't divisible by 4, either.
//		///First tests have shown that there do exist APIs which zero out only the least significant ULONG.
//		///As this would lead to a test pass since the handle is then not NULL yet ends with a nibble value
//		///divisible by 4 we simply introduce another check whether the handle value is unlikely large.
//		///Please refer to the #define in order to understand the decision of the maximum value.
//		if (!hFile || ((ULONGLONG)hFile % 4) || (MAX_HANDLE_VALUE_LIKELY < (ULONGLONG)hFile))
//			continue;
//		
//		*pDebugBuffer = 3;
//
//		for (ULONG candNtReadFile = NT_SYSCALL_START; candNtReadFile < NT_SYSCALL_END; candNtReadFile++) {
//			if(syscallnumNtClose == candNtReadFile)
//				continue;	///Skip the ones we already know...
//
//			ioSb.Status = 0xF000000D;
//			ioSb.Information = 0xDDDDDDDDDDDDDDDD;
//			*(PUSHORT)pNtdllBuffer = 0x0;
//
//			for (ULONGLONG i = 4; i < 0x40; i+=4) {
//				syscallStub(candNtReadFile, hFile, (HANDLE)i, NULL, NULL, &ioSb, pNtdllBuffer, NTDLL_MAX_SIZE, NULL, NULL);
//				if (0xF000000D == ioSb.Status)	///This test has an extremely strong filtering behavior!
//					continue;					///Refer to first use of this check for a detailed explanation.
//
//				if (IMAGE_DOS_SIGNATURE != *(PUSHORT)pNtdllBuffer)
//					continue;
//
//				if ((NTDLL_MIN_SIZE < ioSb.Information) && (ioSb.Information < NTDLL_MAX_SIZE)) {
//					*pDebugBuffer = 6;
//					if ((4 >((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_lfanew) ||
//						((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_lfanew >= (LONG)NTDLL_MAX_SIZE)
//						continue;
//
//					pNtdllPeHdr = (PIMAGE_NT_HEADERS64)((PUCHAR)pNtdllBuffer + ((PIMAGE_DOS_HEADER)pNtdllBuffer)->e_lfanew);
//					if ((pNtdllPeHdr->Signature != IMAGE_NT_SIGNATURE) ||
//						(pNtdllPeHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
//						(pNtdllPeHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
//						continue;
//
//					if ((pNtdllPeHdr->OptionalHeader.NumberOfRvaAndSizes))
//						return syscallStub(syscallnumNtClose, hFile);
//				}
//			}
//		}
//	}
//
//	return STATUS_ORDINAL_NOT_FOUND;
//}
			//}

			//	__try {
			//__except (EXCEPTION_EXECUTE_HANDLER){
			//	return STATUS_UNHANDLED_EXCEPTION;
			//}