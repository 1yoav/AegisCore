// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <winternl.h>
#include <Windows.h>
#include <vector>
#include <tlhelp32.h>
#include <stdio.h>
#include <cstring> // For strlen
#include <string>
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


// Link MinHook library
#if _WIN64
#pragma comment(lib, "MinHook.x64.lib")
#else
#pragma comment(lib, "MinHook.x86.lib")
#endif

typedef struct HookInfo {
    const wchar_t* dllName;
    const char* funcName;
    LPVOID hookFunc;        
    LPVOID* originalFunc;  
}HookInfo;


typedef CLIENT_ID* PCLIENT_ID;

typedef HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
    LPVOID, DWORD, LPDWORD
    );
pCreateRemoteThread fpCreateRemoteThread = nullptr;

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



/////////////////////////////////////
// Hooked functions implementation  //
/////////////////////////////////////

HANDLE WINAPI HookCreateRemoteThread(
    HANDLE a, LPSECURITY_ATTRIBUTES b, SIZE_T c,
    LPTHREAD_START_ROUTINE d, LPVOID e, DWORD f, LPDWORD g
) {
    OutputDebugStringW(L"[API] CreateRemoteThread\n");
    return fpCreateRemoteThread(a, b, c, d, e, f, g);
}

BOOL WINAPI HookLookupPrivilegeValue(LPCWSTR a, LPCWSTR b, PLUID c) {
    OutputDebugStringW(L"[API] LookupPrivilegeValue\n");
    return fpLookupPrivilegeValue(a, b, c);
}

BOOL WINAPI HookWriteProcessMemory(HANDLE a, LPVOID b, LPCVOID c, SIZE_T d, SIZE_T* e) {
    OutputDebugStringW(L"[API] WriteProcessMemory\n");
    return fpWriteProcessMemory(a, b, c, d, e);
}

BOOL WINAPI HookAdjustTokenPrivileges(
    HANDLE a, BOOL b, PTOKEN_PRIVILEGES c, DWORD d,
    PTOKEN_PRIVILEGES e, PDWORD f
) {
    OutputDebugStringW(L"[API] AdjustTokenPrivileges\n");
    return fpAdjustTokenPrivileges(a, b, c, d, e, f);
}

BOOL WINAPI HookOpenProcessToken(HANDLE a, DWORD b, PHANDLE c) {
    OutputDebugStringW(L"[API] OpenProcessToken\n");
    return fpOpenProcessToken(a, b, c);
}

HANDLE WINAPI HookOpenProcess(DWORD a, BOOL b, DWORD c) {
    OutputDebugStringW(L"[API] OpenProcess\n");
    return fpOpenProcess(a, b, c);
}

LPVOID WINAPI HookVirtualAllocEx(HANDLE a, LPVOID b, SIZE_T c, DWORD d, DWORD e) {
    OutputDebugStringW(L"[API] VirtualAllocEx\n");
    return fpVirtualAllocEx(a, b, c, d, e);
}

BOOL WINAPI HookVirtualProtect(LPVOID a, SIZE_T b, DWORD c, PDWORD d) {
    OutputDebugStringW(L"[API] VirtualProtect\n");
    return fpVirtualProtect(a, b, c, d);
}

// ================================
// CreateProcessA
// ================================
BOOL WINAPI HookCreateProcessA(
    LPCSTR a, LPSTR b, LPSECURITY_ATTRIBUTES c, LPSECURITY_ATTRIBUTES d,
    BOOL e, DWORD f, LPVOID g, LPCSTR h, LPSTARTUPINFOA i, LPPROCESS_INFORMATION j
) {
    OutputDebugStringW(L"[API] CreateProcessA\n");
    return fpCreateProcessA(a, b, c, d, e, f, g, h, i, j);
}

// ================================
// CreateProcessW
// ================================
BOOL WINAPI HookCreateProcessW(
    LPCWSTR a, LPWSTR b, LPSECURITY_ATTRIBUTES c, LPSECURITY_ATTRIBUTES d,
    BOOL e, DWORD f, LPVOID g, LPCWSTR h, LPSTARTUPINFOW i, LPPROCESS_INFORMATION j
) {
    OutputDebugStringW(L"[API] CreateProcessW\n");
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
    OutputDebugStringW(L"[API] CreateProcessInternalW\n");
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
    OutputDebugStringW(L"[API] CreateProcessInternalA\n");
    return fpCreateProcessInternalA(a, b, c, d, e, f, g, h, i, j, k, l);
}

// ================================
// Process32Next
// ================================
BOOL WINAPI HookProcess32Next(HANDLE a, LPPROCESSENTRY32 b) {
    OutputDebugStringW(L"[API] Process32Next\n");
    return fpProcess32Next(a, b);
}

// ================================
// Process32First
// ================================
BOOL WINAPI HookProcess32First(HANDLE a, LPPROCESSENTRY32 b) {
    OutputDebugStringW(L"[API] Process32First\n");
    return fpProcess32First(a, b);
}

// ================================
// CreateToolhelp32Snapshot
// ================================
HANDLE WINAPI HookCreateToolhelp32Snapshot(DWORD a, DWORD b) {
    OutputDebugStringW(L"[API] CreateToolhelp32Snapshot\n");
    return fpCreateToolhelp32Snapshot(a, b);
}

// ================================
// NtCreateSection
// ================================
NTSTATUS NTAPI HookNtCreateSection(
    PHANDLE a, ACCESS_MASK b, POBJECT_ATTRIBUTES c,
    PLARGE_INTEGER d, ULONG e, ULONG f, HANDLE g
) {
    OutputDebugStringW(L"[API] NtCreateSection\n");
    return fpNtCreateSection(a, b, c, d, e, f, g);
}

// ================================
// NtMapViewOfSection
// ================================
NTSTATUS NTAPI HookNtMapViewOfSection(
    HANDLE a, HANDLE b, PVOID* c, ULONG_PTR d, SIZE_T e,
    PLARGE_INTEGER f, PSIZE_T g, DWORD h, ULONG i, ULONG j
) {
    OutputDebugStringW(L"[API] NtMapViewOfSection\n");
    return fpNtMapViewOfSection(a, b, c, d, e, f, g, h, i, j);
}

// ================================
// NtUnmapViewOfSection
// ================================
NTSTATUS NTAPI HookNtUnmapViewOfSection(
    HANDLE a, PVOID b
) {
    OutputDebugStringW(L"[API] NtUnmapViewOfSection\n");
    return fpNtUnmapViewOfSection(a, b);
}

// ================================
// QueueUserAPC
// ================================
DWORD WINAPI HookQueueUserAPC(PAPCFUNC a, HANDLE b, ULONG_PTR c) {
    OutputDebugStringW(L"[API] QueueUserAPC\n");
    return fpQueueUserAPC(a, b, c);
}

// ================================
// SuspendThread
// ================================
DWORD WINAPI HookSuspendThread(HANDLE a) {
    OutputDebugStringW(L"[API] SuspendThread\n");
    return fpSuspendThread(a);
}

// ================================
// ResumeThread
// ================================
DWORD WINAPI HookResumeThread(HANDLE a) {
    OutputDebugStringW(L"[API] ResumeThread\n");
    return fpResumeThread(a);
}

// ================================
// RtlCreateUserThread
// ================================
NTSTATUS NTAPI HookRtlCreateUserThread(
    HANDLE a, PSECURITY_DESCRIPTOR b, BOOLEAN c, ULONG d,
    PULONG e, PULONG f, PVOID g, PVOID h, PHANDLE i, PCLIENT_ID j
) {
    OutputDebugStringW(L"[API] RtlCreateUserThread\n");
    return fpRtlCreateUserThread(a, b, c, d, e, f, g, h, i, j);
}

// ================================
// NtCreateThreadEx
// ================================
NTSTATUS NTAPI HookNtCreateThreadEx(
    PHANDLE a, ACCESS_MASK b, POBJECT_ATTRIBUTES c, HANDLE d,
    PVOID e, PVOID f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, PVOID k
) {
    OutputDebugStringW(L"[API] NtCreateThreadEx\n");
    return fpNtCreateThreadEx(a, b, c, d, e, f, g, h, i, j, k);
}

// ================================
// GetThreadContext
// ================================
BOOL WINAPI HookGetThreadContext(HANDLE a, LPCONTEXT b) {
    OutputDebugStringW(L"[API] GetThreadContext\n");
    return fpGetThreadContext(a, b);
}

// ================================
// SetThreadContext
// ================================
BOOL WINAPI HookSetThreadContext(HANDLE a, const CONTEXT* b) {
    OutputDebugStringW(L"[API] SetThreadContext\n");
    return fpSetThreadContext(a, b);
}


std::vector<HookInfo> hooks = {

    // ---------- CreateProcess ----------
    { L"kernel32.dll", "CreateProcessA",
        (LPVOID)&HookCreateProcessA,
        (LPVOID*)&fpCreateProcessA },

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








// ============================================
// DLL Entry Point
// ============================================



DWORD WINAPI nitHook(LPVOID)
{
    if (MH_Initialize() != MH_OK)
    {
        OutputDebugStringW(L"MH_Initialize failed");
        return 0;
    }

    for (const auto& hook : hooks) {
        if (MH_CreateHookApi(hook.dllName, hook.funcName, hook.hookFunc, hook.originalFunc) != MH_OK)
        {
            std::string name = hook.funcName;
            std::wstring msg = std::wstring(L"[HOOK FAIL] ") + std::wstring(name.begin(), name.end());
            OutputDebugStringW(msg.c_str());
        }
    }


    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        OutputDebugStringW(L"MH_EnableHook failed");
    }
    return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Add this function to your dllmain.cpp
        OutputDebugStringW(L"DLL_PROCESS_ATTACH called");
        DisableThreadLibraryCalls(hModule);
        (QueueUserWorkItem(nitHook, nullptr, WT_EXECUTEDEFAULT));

        break;

    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();

        break;
    }

    return TRUE;
}











