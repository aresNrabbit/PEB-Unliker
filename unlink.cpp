#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, *PMY_PEB;

DWORD FindProcessId(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processName, processEntry.szExeFile) == 0) {
                pid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
    return pid;
}

int UnlinkModule(DWORD pid, const wchar_t* moduleName) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        wprintf(L"Failed to open process. Run as Administrator.\n");
        return 0;
    }
    
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    
    if (status != 0) {
        wprintf(L"Failed to query process information.\n");
        CloseHandle(hProcess);
        return 0;
    }
    
    MY_PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    BOOL readResult = ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(MY_PEB), &bytesRead);
    if (!readResult) {
        wprintf(L"Failed to read PEB. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 0;
    }
    
    MY_PEB_LDR_DATA ldr = { 0 };
    readResult = ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(MY_PEB_LDR_DATA), &bytesRead);
    if (!readResult) {
        wprintf(L"Failed to read LDR data.\n");
        CloseHandle(hProcess);
        return 0;
    }
    
    LIST_ENTRY head = ldr.InLoadOrderModuleList;
    LIST_ENTRY current = head;
    
    readResult = ReadProcessMemory(hProcess, head.Flink, &current, sizeof(LIST_ENTRY), &bytesRead);
    if (!readResult) {
        wprintf(L"Failed to read module list.\n");
        CloseHandle(hProcess);
        return 0;
    }
    
    int found = 0;
    while (current.Flink != head.Flink) {
        MY_LDR_DATA_TABLE_ENTRY entry = { 0 };
        
        readResult = ReadProcessMemory(hProcess, current.Flink, &entry, sizeof(MY_LDR_DATA_TABLE_ENTRY), &bytesRead);
        if (!readResult) {
            break;
        }
        
        wchar_t dllName[MAX_PATH] = { 0 };
        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            readResult = ReadProcessMemory(hProcess, entry.BaseDllName.Buffer, dllName, entry.BaseDllName.Length, &bytesRead);
            if (readResult) {
                
                if (_wcsicmp(moduleName, dllName) == 0) {
                    found = 1;
                    
                    wprintf(L"[+] Module found. Base address: %p\n", entry.DllBase);
                    
                    LIST_ENTRY loadLinks = entry.InLoadOrderLinks;
                    LIST_ENTRY memLinks = entry.InMemoryOrderLinks;
                    LIST_ENTRY initLinks = entry.InInitializationOrderLinks;
                    
                    WriteProcessMemory(hProcess, loadLinks.Blink, &loadLinks.Flink, sizeof(PVOID), &bytesRead);
                    WriteProcessMemory(hProcess, loadLinks.Flink, &loadLinks.Blink, sizeof(PVOID), &bytesRead);
                    
                    WriteProcessMemory(hProcess, memLinks.Blink, &memLinks.Flink, sizeof(PVOID), &bytesRead);
                    WriteProcessMemory(hProcess, memLinks.Flink, &memLinks.Blink, sizeof(PVOID), &bytesRead);
                    
                    WriteProcessMemory(hProcess, initLinks.Blink, &initLinks.Flink, sizeof(PVOID), &bytesRead);
                    WriteProcessMemory(hProcess, initLinks.Flink, &initLinks.Blink, sizeof(PVOID), &bytesRead);
                    
                    break;
                }
            }
        }
        
        current = entry.InLoadOrderLinks;
    }
    
    CloseHandle(hProcess);
    return found;
}

int main() {
    wchar_t processName[256] = { 0 };
    wchar_t moduleName[256] = { 0 };
    
    wprintf(L"Target Process Name: ");
    fgetws(processName, 256, stdin);
    processName[wcslen(processName) - 1] = 0;
    
    DWORD pid = FindProcessId(processName);
    if (pid == 0) {
        wprintf(L"Process not found.\n");
        return 1;
    }
    
    wprintf(L"PID: %d\n", pid);
    wprintf(L"DLL to bypass: ");
    fgetws(moduleName, 256, stdin);
    moduleName[wcslen(moduleName) - 1] = 0;
    
    wprintf(L"Opening process %d...\n", pid);
    wprintf(L"Searching for %s...\n", moduleName);
    
    int result = UnlinkModule(pid, moduleName);
    
    if (result) {
        wprintf(L"SUCCESS Module \"%s\" has been bypassed from %s.\n", moduleName, processName);
    } else {
        wprintf(L"Module not found.\n");
        return 1;
    }
    
    system("pause");
    return 0;
}
