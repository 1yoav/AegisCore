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

DWORD GetPIDByName(const wchar_t* name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, name) == 0) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return 0;
}



int main()
{
	//get the pipe server up and running
    std::thread pipe([]() { createPipe((wchar_t*)L"\\\\.\\pipe\\my_pipe"); });
    pipe.detach();
    Sleep(2000);



	//load the hooking DLL
    /*HMODULE hDLL = LoadLibrary(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll");
	Sleep(2000);*/
    // ---------------------------
    // 2. Toolhelp32Snapshot / Process32
    // ---------------------------
    /*HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    Process32First(snap, &pe);
    while (Process32Next(snap, &pe));
    CloseHandle(snap);*/

    //FreeLibrary(GetModuleHandleW(L"C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll"));

    DWORD pid = GetPIDByName(L"chrome.exe");
    // Open the target process with permissions to create threads and write memory
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cout << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }
    // Path to the DLL to inject
    const char* dllPath = "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll";
    size_t pathLen = strlen(dllPath) + 1;
    // Allocate memory in the target process
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory)
    {
        std::cout << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    // Write the DLL path into the target process memory
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, pathLen, NULL))
    {
        std::cout << "Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    // Get the address of LoadLibraryA
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        std::cout << "Failed to get LoadLibraryA address. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    // Create a remote thread that calls LoadLibraryA with our DLL path
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteMemory,
        0,
        NULL
    );

    if (!hThread)
    {
        std::cout << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "Remote thread created successfully!" << std::endl;
        WaitForSingleObject(hThread, INFINITE);
        std::cin >> std::ws; // Wait for user input before proceeding
        CloseHandle(hThread);
    }

    // Cleanup
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

   return 0;


}

