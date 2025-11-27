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
    std::thread pipe([]() { createPipe((wchar_t*)L"\\\\.\\pipe\\my_pipe"); });
    pipe.detach();
    Sleep(2000);

	//load the hooking DLL
    HMODULE minHook = LoadLibrary(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\MinHook.x64.dll");
    HMODULE hDLL = LoadLibrary(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll");
	Sleep(2000);
    printf("DLL loaded. Testing APIs...\n");

    // ---------------------------
    // 2. Toolhelp32Snapshot / Process32
    // ---------------------------
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    Process32First(snap, &pe);
    while (Process32Next(snap, &pe));
    CloseHandle(snap);

   

    printf("All tests finished!\n");
   return 0;


}

