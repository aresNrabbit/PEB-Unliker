# PEB Unlinker
### Windows Internals | PEB Manipulation | DLL Loader Structures

## Overview

PEB Unlinker is a C++ Windows internals research tool that explores the manipulation of DLL loader entries within a target process.

It interacts with the Process Environment Block (PEB) and its loader data structures to locate a specified DLL and unlink its corresponding entries from the process's loader module lists.

## How It Works

The program follows these stages:

1. **Process Enumeration**
   Uses the Windows Toolhelp32 API to enumerate running processes and identify the target process by executable name.

2. **Process Information Retrieval**
   Opens the target process and uses `NtQueryInformationProcess` to retrieve its `PROCESS_BASIC_INFORMATION`, including the PEB address.

3. **PEB Inspection**
   Reads the target process's PEB to locate its `PEB_LDR_DATA` structure.

4. **Loader Data Inspection**
   Examines the loader's linked-list structures to identify loaded DLL entries.

5. **Module Identification**
   Compares the requested DLL name against the `BaseDllName` stored in loader entries.

6. **Loader List Manipulation**
   The implementation attempts to unlink the identified module's entries from the three PEB loader lists.

## Internal Structures

| Structure | Purpose |
|---|---|
| PEB | Process Environment Block |
| PEB_LDR_DATA | Contains loader information |
| LDR_DATA_TABLE_ENTRY | Stores DLL loader metadata |
| LIST_ENTRY | Implements doubly linked lists |
| PROCESS_BASIC_INFORMATION | Contains basic process information |

## Windows APIs

- `CreateToolhelp32Snapshot`
- `Process32FirstW`
- `Process32NextW`
- `OpenProcess`
- `NtQueryInformationProcess`
- `ReadProcessMemory`
- `WriteProcessMemory`
- `CloseHandle`

## Loader Lists

The implementation interacts with three loader lists:

- **InLoadOrderModuleList** — maintains modules in load order.
- **InMemoryOrderModuleList** — maintains modules in memory order.
- **InInitializationOrderModuleList** — maintains modules in initialization order.

## What It Does

- Enumerates running Windows processes.
- Identifies a target process by executable name.
- Retrieves its PEB address.
- Inspects loader-related process structures.
- Searches for a specified DLL.
- Attempts to unlink the DLL's loader-list entries.

## Important Technical Note

Unlinking a DLL from the PEB loader lists does not unload the DLL or erase its memory image. Other module-enumeration mechanisms may still identify it.

The implementation is experimental and depends on internal Windows structures whose layouts can vary across architectures and Windows versions.

## Technologies

- C++
- Windows API
- Native Windows API
- PEB / LDR Internals
- Cross-Process Memory Inspection
- Windows Process Architecture
