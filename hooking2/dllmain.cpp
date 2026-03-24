﻿// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <winternl.h>
#include <iostream>
#include <Windows.h>
#include <thread>
#include <psapi.h>
#include <sstream>
#include <locale>
#include <codecvt> // Deprecated in C++17
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <stdio.h>
#include <mutex>
#include <cstring> // For strlen
#include "MinHook.h"

//***********************************
// Declarations of hooked functions *
//***********************************

//CreateProcessA
//• CreateProcessW
//• CreateProcessInternalW
//• CreateProcessInternalA
//• Process32Next
//• Process32First
//• CreateToolhelp32Snapshot
//• OpenProcess
//• VirtualAllocEx
//• LookupPrivilegeValue
//• AdjustTokenPrivileges
//• OpenProcessToken
//• VirtualProtect
//• WriteProcessMemory
//• NtUnmapViewOfSection
//• NtCreateSection
//• NtMapViewOfSection
//• QueueUserAPCprintf
//• SuspendThread
//• ResumeThread
//• CreateRemoteThread
//• RtlCreateUserThread
//• NtCreateThreadEx
//• GetThreadContext
//• SetThreadContext


typedef MH_STATUS(WINAPI* pMH_Initialize)();
typedef MH_STATUS(WINAPI* pMH_Uninitialize)();
typedef MH_STATUS(WINAPI* pMH_CreateHookApi)(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID* ppOriginal);
typedef MH_STATUS(WINAPI* pMH_EnableHook)(LPVOID pTarget);
typedef MH_STATUS(WINAPI* pMH_DisableHook)(LPVOID pTarget);

// ------------------- Globals -------------------
HMODULE g_hMinHook;

pMH_Initialize      g_MH_Initialize;
pMH_Uninitialize    g_MH_Uninitialize;
pMH_CreateHookApi   g_MH_CreateHookApi;
pMH_EnableHook      g_MH_EnableHook;
pMH_DisableHook     g_MH_DisableHook;

HMODULE hModulee;

//defins global variables and types
typedef struct HookInfo {
    const wchar_t* dllName;
    const char* funcName;
    LPVOID hookFunc;
    LPVOID* originalFunc;
}HookInfo;

std::vector<std::string> loggedApi;
std::mutex logMutex;
typedef CLIENT_ID* PCLIENT_ID;

const wchar_t* pipeName = L"\\\\.\\pipe\\my_pipe";

//declare logging function
void LogHookedFunction(std::string functionName);


typedef HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
    LPVOID, DWORD, LPDWORD
    );
pCreateRemoteThread fpCreateRemoteThread = nullptr;

typedef BOOL(WINAPI* pReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );
pReadFile fpReadFile = nullptr;

typedef VOID(WINAPI* pSleep)(
    DWORD dwMilliseconds
    );
pSleep fpSleep = nullptr;

typedef NTSTATUS(NTAPI* pNtTerminateProcess)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
    );
pNtTerminateProcess fpNtTerminateProcess = nullptr;



typedef BOOL(WINAPI* pCloseHandle)(
    HANDLE hObject
    );
pCloseHandle fpCloseHandle = nullptr;

typedef BOOL(WINAPI* pWriteFile)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );
pWriteFile fpWriteFile = nullptr;

typedef BOOL(WINAPI* pLookupPrivilegeValue)(
    LPCWSTR, LPCWSTR, PLUID
    );
pLookupPrivilegeValue fpLookupPrivilegeValue = nullptr;

typedef BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*
    );
pWriteProcessMemory fpWriteProcessMemory = nullptr;

typedef BOOL(WINAPI* pAdjustTokenPrivileges)(
    HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD
    );


pAdjustTokenPrivileges fpAdjustTokenPrivileges = nullptr;

typedef BOOL(WINAPI* pOpenProcessToken)(
    HANDLE, DWORD, PHANDLE
    );
pOpenProcessToken fpOpenProcessToken = nullptr;

typedef HANDLE(WINAPI* pOpenProcess)(
    DWORD, BOOL, DWORD
    );
pOpenProcess fpOpenProcess = nullptr;

typedef LPVOID(WINAPI* pVirtualAllocEx)(
    HANDLE, LPVOID, SIZE_T, DWORD, DWORD
    );
pVirtualAllocEx fpVirtualAllocEx = nullptr;

typedef BOOL(WINAPI* pVirtualProtect)(
    LPVOID, SIZE_T, DWORD, PDWORD
    );
pVirtualProtect fpVirtualProtect = nullptr;

typedef BOOL(WINAPI* pCreateProcessA)(LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );
pCreateProcessA fpCreateProcessA = nullptr;

typedef BOOL(WINAPI* pCreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION
    );
pCreateProcessW fpCreateProcessW = nullptr;

typedef BOOL(WINAPI* pCreateProcessInternalW)(
    HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION,
    HANDLE
    );
pCreateProcessInternalW fpCreateProcessInternalW = nullptr;

typedef BOOL(WINAPI* pCreateProcessInternalA)(
    HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION,
    HANDLE
    );
pCreateProcessInternalA fpCreateProcessInternalA = nullptr;

typedef BOOL(WINAPI* pProcess32Next)(HANDLE, LPPROCESSENTRY32);
pProcess32Next fpProcess32Next = nullptr;

typedef BOOL(WINAPI* pProcess32First)(HANDLE, LPPROCESSENTRY32);
pProcess32First fpProcess32First = nullptr;

typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
pCreateToolhelp32Snapshot fpCreateToolhelp32Snapshot = nullptr;

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE
    );
pNtCreateSection fpNtCreateSection = nullptr;

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG
    );
pNtMapViewOfSection fpNtMapViewOfSection = nullptr;

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE, PVOID
    );
pNtUnmapViewOfSection fpNtUnmapViewOfSection = nullptr;

typedef DWORD(WINAPI* pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
pQueueUserAPC fpQueueUserAPC = nullptr;

typedef DWORD(WINAPI* pSuspendThread)(HANDLE);
pSuspendThread fpSuspendThread = nullptr;

typedef DWORD(WINAPI* pResumeThread)(HANDLE);
pResumeThread fpResumeThread = nullptr;

typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
    PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID
    );
pRtlCreateUserThread fpRtlCreateUserThread = nullptr;

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
    );
pNtCreateThreadEx fpNtCreateThreadEx = nullptr;

typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);
pGetThreadContext fpGetThreadContext = nullptr;

typedef BOOL(WINAPI* pSetThreadContext)(HANDLE, const CONTEXT*);
pSetThreadContext fpSetThreadContext = nullptr;

typedef NTSTATUS(NTAPI* pNtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
    );
pNtSetInformationFile fpNtSetInformationFile = nullptr;

typedef NTSTATUS(NTAPI* pNtDeleteFile)(
    POBJECT_ATTRIBUTES ObjectAttributes
    );
pNtDeleteFile fpNtDeleteFile = nullptr;



/////////////////////////////////////
// Hooked functions implementation  //
/////////////////////////////////////

HANDLE WINAPI HookCreateRemoteThread(
    HANDLE a, LPSECURITY_ATTRIBUTES b, SIZE_T c,
    LPTHREAD_START_ROUTINE d, LPVOID e, DWORD f, LPDWORD g
) {
    LogHookedFunction("CreateRemoteThread");
    return fpCreateRemoteThread(a, b, c, d, e, f, g);
}

BOOL WINAPI HookLookupPrivilegeValue(LPCWSTR a, LPCWSTR b, PLUID c) {
    LogHookedFunction("LookupPrivilegeValue");
    return fpLookupPrivilegeValue(a, b, c);
}

BOOL WINAPI HookWriteProcessMemory(HANDLE a, LPVOID b, LPCVOID c, SIZE_T d, SIZE_T* e) {
    LogHookedFunction("WriteProcessMemory");
    return fpWriteProcessMemory(a, b, c, d, e);
}

BOOL WINAPI HookWriteFile(
    HANDLE a, LPCVOID b, DWORD c, LPDWORD d, LPOVERLAPPED e
) {
    LogHookedFunction("WriteFile");
    return fpWriteFile(a, b, c, d, e);
}

BOOL WINAPI HookReadFile(
    HANDLE a, LPVOID b, DWORD c, LPDWORD d, LPOVERLAPPED e
) {
    LogHookedFunction("ReadFile");
    return fpReadFile(a, b, c, d, e);
}

BOOL WINAPI HookCloseHandle(HANDLE a) {
    LogHookedFunction("CloseHandle");
    return fpCloseHandle(a);
}

BOOL WINAPI HookSleep(DWORD a) {
    LogHookedFunction("Sleep");
    fpSleep(a);
    return TRUE;
}

BOOL WINAPI HookAdjustTokenPrivileges(
    HANDLE a, BOOL b, PTOKEN_PRIVILEGES c, DWORD d,
    PTOKEN_PRIVILEGES e, PDWORD f
) {
    LogHookedFunction("AdjustTokenPrivileges");
    return fpAdjustTokenPrivileges(a, b, c, d, e, f);
}

BOOL WINAPI HookOpenProcessToken(HANDLE a, DWORD b, PHANDLE c) {
    LogHookedFunction("OpenProcessToken");
    return fpOpenProcessToken(a, b, c);
}

HANDLE WINAPI HookOpenProcess(DWORD a, BOOL b, DWORD c) {
    LogHookedFunction("OpenProcess");
    return fpOpenProcess(a, b, c);
}

LPVOID WINAPI HookVirtualAllocEx(HANDLE a, LPVOID b, SIZE_T c, DWORD d, DWORD e) {
    LogHookedFunction("VirtualAllocEx");
    return fpVirtualAllocEx(a, b, c, d, e);
}

BOOL WINAPI HookVirtualProtect(LPVOID a, SIZE_T b, DWORD c, PDWORD d) {
    LogHookedFunction("VirtualProtect");
    return fpVirtualProtect(a, b, c, d);
}

// ================================
// CreateProcessA
// ================================
BOOL WINAPI HookCreateProcessA(
    LPCSTR a, LPSTR b, LPSECURITY_ATTRIBUTES c, LPSECURITY_ATTRIBUTES d,
    BOOL e, DWORD f, LPVOID g, LPCSTR h, LPSTARTUPINFOA i, LPPROCESS_INFORMATION j
) {
    LogHookedFunction("CreateProcessA");
    return fpCreateProcessA(a, b, c, d, e, f, g, h, i, j);
}

// ================================
// CreateProcessW
// ================================
BOOL WINAPI HookCreateProcessW(
    LPCWSTR a, LPWSTR b, LPSECURITY_ATTRIBUTES c, LPSECURITY_ATTRIBUTES d,
    BOOL e, DWORD f, LPVOID g, LPCWSTR h, LPSTARTUPINFOW i, LPPROCESS_INFORMATION j
) {
    LogHookedFunction("CreateProcessW");
    return fpCreateProcessW(a, b, c, d, e, f, g, h, i, j);
}

// ================================
// CreateProcessInternalW
// ================================
BOOL WINAPI HookCreateProcessInternalW(
    HANDLE a, LPCWSTR b, LPWSTR c, LPSECURITY_ATTRIBUTES d, LPSECURITY_ATTRIBUTES e,
    BOOL f, DWORD g, LPVOID h, LPCWSTR i, LPSTARTUPINFOW j,
    LPPROCESS_INFORMATION k, HANDLE l
) {
    LogHookedFunction("CreateProcessInternalW");
    return fpCreateProcessInternalW(a, b, c, d, e, f, g, h, i, j, k, l);
}

// ================================
// CreateProcessInternalA
// ================================
BOOL WINAPI HookCreateProcessInternalA(
    HANDLE a, LPCSTR b, LPSTR c, LPSECURITY_ATTRIBUTES d, LPSECURITY_ATTRIBUTES e,
    BOOL f, DWORD g, LPVOID h, LPCSTR i, LPSTARTUPINFOA j,
    LPPROCESS_INFORMATION k, HANDLE l
) {
    LogHookedFunction("CreateProcessInternalA");
    return fpCreateProcessInternalA(a, b, c, d, e, f, g, h, i, j, k, l);
}

// ================================
// Process32Next
// ================================
BOOL WINAPI HookProcess32Next(HANDLE a, LPPROCESSENTRY32 b) {
    LogHookedFunction("Process32Next");
    return fpProcess32Next(a, b);
}

// ================================
// Process32First
// ================================
BOOL WINAPI HookProcess32First(HANDLE a, LPPROCESSENTRY32 b) {
    LogHookedFunction("Process32First");
    return fpProcess32First(a, b);
}

// ================================
// CreateToolhelp32Snapshot
// ================================
HANDLE WINAPI HookCreateToolhelp32Snapshot(DWORD a, DWORD b) {
    OutputDebugStringW(L"tool32 snapshot called");
    LogHookedFunction("CreateToolhelp32Snapshot");
    return fpCreateToolhelp32Snapshot(a, b);
}

// ================================
// NtCreateSection
// ================================
NTSTATUS NTAPI HookNtCreateSection(
    PHANDLE a, ACCESS_MASK b, POBJECT_ATTRIBUTES c,
    PLARGE_INTEGER d, ULONG e, ULONG f, HANDLE g
) {
    LogHookedFunction("NtCreateSection");
    return fpNtCreateSection(a, b, c, d, e, f, g);
}

NTSTATUS NTAPI HookNtDeleteFile(
    POBJECT_ATTRIBUTES a    // ObjectAttributes 
) {
    if (a && a->ObjectName && a->ObjectName->Buffer) {
        std::wstring name(a->ObjectName->Buffer, a->ObjectName->Length / sizeof(wchar_t));

        for (auto& c : name) c = towlower(c);

        if (name.find(L"aegiscore-av") != std::wstring::npos) {
            LogHookedFunction("Blocked Delete on NtDeleteFile: aegiscore-av");
            return 0xC0000022; // STATUS_ACCESS_DENIED
        }
    }

    return fpNtDeleteFile(a);
}


// ================================
// NtMapViewOfSection
// ================================
NTSTATUS NTAPI HookNtMapViewOfSection(
    HANDLE a, HANDLE b, PVOID* c, ULONG_PTR d, SIZE_T e,
    PLARGE_INTEGER f, PSIZE_T g, DWORD h, ULONG i, ULONG j
) {
    LogHookedFunction("NtMapViewOfSection");
    return fpNtMapViewOfSection(a, b, c, d, e, f, g, h, i, j);
}

// ================================
// NtUnmapViewOfSection
// ================================
NTSTATUS NTAPI HookNtUnmapViewOfSection(
    HANDLE a, PVOID b
) {
    LogHookedFunction("NtUnmapViewOfSection");
    return fpNtUnmapViewOfSection(a, b);
}

// ================================
// QueueUserAPC
// ================================
DWORD WINAPI HookQueueUserAPC(PAPCFUNC a, HANDLE b, ULONG_PTR c) {
    LogHookedFunction("QueueUserAPC");
    return fpQueueUserAPC(a, b, c);
}

// ================================
// SuspendThread
// ================================
DWORD WINAPI HookSuspendThread(HANDLE a) {
    LogHookedFunction("SuspendThread");
    return fpSuspendThread(a);
}

// ================================
// ResumeThread
// ================================
DWORD WINAPI HookResumeThread(HANDLE a) {
    LogHookedFunction("ResumeThread");
    return fpResumeThread(a);
}

// ================================
// RtlCreateUserThread
// ================================
NTSTATUS NTAPI HookRtlCreateUserThread(
    HANDLE a, PSECURITY_DESCRIPTOR b, BOOLEAN c, ULONG d,
    PULONG e, PULONG f, PVOID g, PVOID h, PHANDLE i, PCLIENT_ID j
) {
    LogHookedFunction("RtlCreateUserThread");
    return fpRtlCreateUserThread(a, b, c, d, e, f, g, h, i, j);
}

NTSTATUS NTAPI HookNtSetInformationFile(
    HANDLE a,               // FileHandle
    PIO_STATUS_BLOCK b,     // IoStatusBlock 
    PVOID c,                // FileInformation
    ULONG d,                // Length
    int e                   // FileInformationClass
) {
    // 13 = FileDispositionInformation, 64 = FileDispositionInformationEx
    if (e == 13 || e == 64 || e == 10) {
        wchar_t path[MAX_PATH];
        if (GetFinalPathNameByHandleW(a, path, MAX_PATH, VOLUME_NAME_DOS) > 0) {
            _wcslwr_s(path, MAX_PATH); // transfer to lowercase for case-insensitive comparison
            if (wcsstr(path, L"aegiscore-av")) {
                LogHookedFunction("Blocked Delete on NtSetInformationFile: aegiscore-av");
                return 0xC0000022; // STATUS_ACCESS_DENIED
            }
        }
    }

    return fpNtSetInformationFile(a, b, c, d, (FILE_INFORMATION_CLASS)e);
}

NTSTATUS NTAPI HookNtTerminateProcess(
    HANDLE a,               // ProcessHandle
    NTSTATUS b              // ExitStatus
) {
    if (a != NULL && a != (HANDLE)-1) {
        wchar_t procName[MAX_PATH];
        if (GetModuleFileNameExW(a, NULL, procName, MAX_PATH) > 0) {
            _wcslwr_s(procName, MAX_PATH);
            if (wcsstr(procName, L"aegiscore-av")) {
                LogHookedFunction("Blocked Termination of aegiscore-av");
                return 0xC0000022; // STATUS_ACCESS_DENIED
            }
        }
    }

    return fpNtTerminateProcess(a, b);
}

// ================================
// NtCreateThreadEx
// ================================
NTSTATUS NTAPI HookNtCreateThreadEx(
    PHANDLE a, ACCESS_MASK b, POBJECT_ATTRIBUTES c, HANDLE d,
    PVOID e, PVOID f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, PVOID k
) {
    LogHookedFunction("NtCreateThreadEx");
    return fpNtCreateThreadEx(a, b, c, d, e, f, g, h, i, j, k);
}

// ================================
// GetThreadContext
// ================================
BOOL WINAPI HookGetThreadContext(HANDLE a, LPCONTEXT b) {
    LogHookedFunction("GetThreadContext");
    return fpGetThreadContext(a, b);
}

// ================================
// SetThreadContext
// ================================
BOOL WINAPI HookSetThreadContext(HANDLE a, const CONTEXT* b) {
    LogHookedFunction("SetThreadContext");
    return fpSetThreadContext(a, b);
}


std::vector<HookInfo> hooks = {

    // ---------- CreateProcess ----------
    { L"kernel32.dll", "CreateProcessA",
        (LPVOID)&HookCreateProcessA,
        (LPVOID*)&fpCreateProcessA },

    { L"kernel32.dll", "ReadFile",
    (LPVOID)&HookReadFile,
    (LPVOID*)&fpReadFile },

    { L"kernel32.dll", "WriteFile",
    (LPVOID)&HookWriteFile,
    (LPVOID*)&fpWriteFile },

    { L"ntdll.dll", "NtSetInformationFile",
    (LPVOID)&HookNtSetInformationFile,
    (LPVOID*)&fpNtSetInformationFile },

    { L"ntdll.dll", "NtTerminateProcess",
    (LPVOID)&HookNtTerminateProcess,
    (LPVOID*)&fpNtTerminateProcess },

    { L"ntdll.dll", "NtDeleteFile",
        (LPVOID)&HookNtDeleteFile,
        (LPVOID*)&fpNtDeleteFile },

    { L"kernel32.dll", "CloseHandle",
    (LPVOID)&HookCloseHandle,
    (LPVOID*)&fpCloseHandle },

    { L"kernel32.dll", "Sleep",
    (LPVOID)&HookSleep,
    (LPVOID*)&fpSleep },

    { L"kernel32.dll", "CreateProcessW",
        (LPVOID)&HookCreateProcessW,
        (LPVOID*)&fpCreateProcessW },

    { L"kernel32.dll", "CreateProcessInternalW",
        (LPVOID)&HookCreateProcessInternalW,
        (LPVOID*)&fpCreateProcessInternalW },

    { L"kernel32.dll", "CreateProcessInternalA",
        (LPVOID)&HookCreateProcessInternalA,
        (LPVOID*)&fpCreateProcessInternalA },

        // ---------- Toolhelp Snapshot / Process32 ----------
        { L"kernel32.dll", "CreateToolhelp32Snapshot",
            (LPVOID)&HookCreateToolhelp32Snapshot,
            (LPVOID*)&fpCreateToolhelp32Snapshot },

        { L"kernel32.dll", "Process32First",
            (LPVOID)&HookProcess32First,
            (LPVOID*)&fpProcess32First },

        { L"kernel32.dll", "Process32Next",
            (LPVOID)&HookProcess32Next,
            (LPVOID*)&fpProcess32Next },

            // ---------- Core process injection ----------
            { L"kernel32.dll", "OpenProcess",
                (LPVOID)&HookOpenProcess,
                (LPVOID*)&fpOpenProcess },

            { L"kernel32.dll", "VirtualAllocEx",
                (LPVOID)&HookVirtualAllocEx,
                (LPVOID*)&fpVirtualAllocEx },

            { L"kernel32.dll", "WriteProcessMemory",
                (LPVOID)&HookWriteProcessMemory,
                (LPVOID*)&fpWriteProcessMemory },

            { L"kernel32.dll", "VirtualProtect",
                (LPVOID)&HookVirtualProtect,
                (LPVOID*)&fpVirtualProtect },

            { L"kernel32.dll", "OpenProcessToken",
                (LPVOID)&HookOpenProcessToken,
                (LPVOID*)&fpOpenProcessToken },

                // ---------- Privileges ----------
                { L"advapi32.dll", "LookupPrivilegeValueW",
                    (LPVOID)&HookLookupPrivilegeValue,
                    (LPVOID*)&fpLookupPrivilegeValue },

                { L"advapi32.dll", "AdjustTokenPrivileges",
                    (LPVOID)&HookAdjustTokenPrivileges,
                    (LPVOID*)&fpAdjustTokenPrivileges },

                    //// ---------- NT Native API (Ntdll) ----------
                    //{ L"ntdll.dll", "NtCreateSection",
                    //    (LPVOID)&HookNtCreateSection,
                    //    (LPVOID*)&fpNtCreateSection },

                    //{ L"ntdll.dll", "NtMapViewOfSection",
                    //    (LPVOID)&HookNtMapViewOfSection,
                    //    (LPVOID*)&fpNtMapViewOfSection },

                    //{ L"ntdll.dll", "NtUnmapViewOfSection",
                    //    (LPVOID)&HookNtUnmapViewOfSection,
                    //    (LPVOID*)&fpNtUnmapViewOfSection },

                    { L"ntdll.dll", "NtCreateThreadEx",
                        (LPVOID)&HookNtCreateThreadEx,
                        (LPVOID*)&fpNtCreateThreadEx },

                        // ---------- Thread context / APC ----------
                        { L"kernel32.dll", "QueueUserAPC",
                            (LPVOID)&HookQueueUserAPC,
                            (LPVOID*)&fpQueueUserAPC },

                        { L"kernel32.dll", "SuspendThread",
                            (LPVOID)&HookSuspendThread,
                            (LPVOID*)&fpSuspendThread },

                        { L"kernel32.dll", "ResumeThread",
                            (LPVOID)&HookResumeThread,
                            (LPVOID*)&fpResumeThread },

                        { L"kernel32.dll", "GetThreadContext",
                            (LPVOID)&HookGetThreadContext,
                            (LPVOID*)&fpGetThreadContext },

                        { L"kernel32.dll", "SetThreadContext",
                            (LPVOID)&HookSetThreadContext,
                            (LPVOID*)&fpSetThreadContext },

                            // ---------- Remote thread creation ----------
                            { L"kernel32.dll", "CreateRemoteThread",
                                (LPVOID)&HookCreateRemoteThread,
                                (LPVOID*)&fpCreateRemoteThread },

                            { L"ntdll.dll", "RtlCreateUserThread",
                                (LPVOID)&HookRtlCreateUserThread,
                                (LPVOID*)&fpRtlCreateUserThread },

};

void unloadHooking()
{
    Sleep(1000); // Ensure all operations are completed before unhooking
    if (g_MH_DisableHook != nullptr) {
        g_MH_DisableHook(MH_ALL_HOOKS);
    }

    if (g_MH_Uninitialize != nullptr) {
        g_MH_Uninitialize();
    }

    Sleep(100);

    if (g_hMinHook) {
        FreeLibrary(g_hMinHook);
    }
}

///format: <num of logs><log1><log2>....<log N>
//send logs to named pipe
void sendLogs()
{
    while (true)
    {
        logMutex.lock();
        if (loggedApi.empty())
        {
            logMutex.unlock();
            Sleep(10000); // Sleep for 10 seconds if there are no logs
            continue;
        }

        //create the msg
        std::string msg;
        for (auto item : loggedApi)
        {
            msg += item;
        }
        msg += "END_WINDOW\n";


        loggedApi.clear();
        logMutex.unlock();



        if (!WaitNamedPipeW(pipeName, 2000))
        {
            return;
        }

        HANDLE hPipe = CreateFileW(
            pipeName,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hPipe != INVALID_HANDLE_VALUE)
        {
            fpWriteFile(hPipe, msg.c_str(), (DWORD)msg.size(), NULL, NULL);
            fpCloseHandle(hPipe);
        }
        Sleep(10000); // Send logs every 10 seconds
    }
}




//create log entry
void LogHookedFunction(std::string functionName)
{
    static DWORD pid = 0;
    if (pid == 0)
        pid = GetCurrentProcessId();

    std::string msg = functionName + "\n";

    logMutex.lock();
    if (loggedApi.empty())
    {
        loggedApi.push_back(std::to_string(pid) + "\n");
    }
    loggedApi.push_back(msg);
    logMutex.unlock();
}











// ============================================
// DLL Entry Point
// ============================================



DWORD WINAPI nitHook(LPVOID)
{
    //all the paragraph for achive absolute path for the minhook dll
    HMODULE hCurrentModule = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)nitHook, &hCurrentModule);
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(hCurrentModule, path, MAX_PATH);
    std::wstring ws(path);
    std::wstring directory = ws.substr(0, ws.find_last_of(L"\\/"));
    std::wstring minHookPath = directory + L"\\MinHook.x64.dll";

    g_hMinHook = LoadLibraryW(minHookPath.c_str());
    //g_hMinHook = LoadLibrary(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\MinHook.x64.dll");
    if (!g_hMinHook) {
        OutputDebugStringW(L"LoadLibraryA(MinHook) failed\n");
        return 0;
    }
    g_MH_Initialize = (pMH_Initialize)GetProcAddress(g_hMinHook, "MH_Initialize");
    g_MH_Uninitialize = (pMH_Uninitialize)GetProcAddress(g_hMinHook, "MH_Uninitialize");
    g_MH_CreateHookApi = (pMH_CreateHookApi)GetProcAddress(g_hMinHook, "MH_CreateHookApi");
    g_MH_EnableHook = (pMH_EnableHook)GetProcAddress(g_hMinHook, "MH_EnableHook");
    g_MH_DisableHook = (pMH_DisableHook)GetProcAddress(g_hMinHook, "MH_DisableHook");


    if (g_MH_Initialize() != MH_OK)
    {
        OutputDebugStringW(L"MH_Initializee failed\n");
        return 0;
    }



    for (const auto& hook : hooks) {
        if (g_MH_CreateHookApi(hook.dllName, hook.funcName, hook.hookFunc, hook.originalFunc) != MH_OK)
        {
            std::string name = hook.funcName;
            std::wstring msg = std::wstring(L"[HOOK FAIL] ") + std::wstring(name.begin(), name.end()) + std::wstring(L"\n");
            OutputDebugStringW(msg.c_str());
        }
    }

    g_MH_EnableHook(MH_ALL_HOOKS); // Enable all hooks


    //create thread to send logsjk
    sendLogs();
    unloadHooking();
    FreeLibraryAndExitThread(hModulee, 0);
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Add this function to your dllmain.cpp
        hModulee = hModule;
        DisableThreadLibraryCalls(hModule);
        CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)nitHook, NULL, 0, NULL));
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}











