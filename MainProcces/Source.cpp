#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <iostream>
#include "pipe.h"
#include <thread>


void log(const wchar_t* msg)
{
    wchar_t buffer[512];
    swprintf_s(buffer, 512, L"%s\n", msg);
    OutputDebugStringW(buffer);
}

int main()
{
	//load the hooking DLL
    HMODULE minHook = LoadLibrary(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\MinHook.x64.dll");
    HMODULE hDLL = LoadLibrary(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll");
    
    // Fix the thread creation line in main:
    std::thread pipe([]() { createPipe((wchar_t*)L"\\\\.\\pipe\\my_pipe"); });
	pipe.detach();

	Sleep(2000); // Wait for 2 seconds to ensure the pipe thread is running

    printf("DLL loaded. Testing APIs...\n");

    // ---------------------------
    // 1. CreateProcessA / W
    // ---------------------------
    STARTUPINFOA siA = { sizeof(siA) };
    PROCESS_INFORMATION piA;

    CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE, 0, NULL, NULL,
        &siA, &piA
    );
    CloseHandle(piA.hProcess);
    CloseHandle(piA.hThread);

    // ---------------------------
    // 2. Toolhelp32Snapshot / Process32
    // ---------------------------
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    Process32First(snap, &pe);
    while (Process32Next(snap, &pe));
    CloseHandle(snap);

    // ---------------------------
    // 3. VirtualAllocEx (self-process)
    // ---------------------------
    LPVOID mem = VirtualAllocEx(
        GetCurrentProcess(),
        NULL,
        1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    // ---------------------------
    // 4. WriteProcessMemory (self)
    // ---------------------------
    if (mem) {
        int x = 123;
        WriteProcessMemory(
            GetCurrentProcess(),
            mem,
            &x,
            sizeof(x),
            NULL
        );
    }

    // ---------------------------
    // 5. Get/SetThreadContext
    // ---------------------------
    HANDLE t = GetCurrentThread();
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(t, &ctx);
    SetThreadContext(t, &ctx);

    // ---------------------------
    // 6. QueueUserAPC
    // ---------------------------
    QueueUserAPC((PAPCFUNC)MessageBeep, t, 0);

    // ---------------------------
    // 7. Suspend/ResumeThread (self)
    // ---------------------------
    HANDLE selfThread = GetCurrentThread();
    SuspendThread(selfThread);   // will resume immediately
    ResumeThread(selfThread);

    printf("All tests finished!\n");
   return 0;


}

