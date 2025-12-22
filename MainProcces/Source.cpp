#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <iostream>
#include "pipe.h"
#include <thread>
#include "programsValidation.h"

size_t pathLen;
const char* dllPath;

void log(const wchar_t* msg)
{
    wchar_t buffer[512];
    swprintf_s(buffer, 512, L"%s\n", msg);
    OutputDebugStringW(buffer);
}


int injectHooking(HANDLE hProcess)
{
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
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    // Cleanup
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;



}


int main()
{
	//get the pipe server up and running
    std::thread pipe([]() { createPipe((wchar_t*)L"\\\\.\\pipe\\my_pipe"); });
    pipe.detach();
    Sleep(2000);



    dllPath = "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll";
    pathLen = strlen(dllPath) + 1;


    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);


    if (Process32FirstW(snapshot, &pe))
    {
        do {
            if (ShouldConsiderHooking(pe.th32ProcessID) && GetCurrentProcessId() != pe.th32ProcessID && wcscmp(pe.szExeFile, L"notepad++.exe") == 0 ) //proc ces are forbid in 3 condition. 1 - system path. 2 - exsist on boot. 3 - got hige privilges. 
            {
                std::wcout << L"[allow] "
                    << pe.th32ProcessID << L"| "
                    << pe.szExeFile << std::endl;
                injectHooking(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID));                
            }
             else
             {
                 /*std::wcout << L"[Forbid] "
                     << pe.th32ProcessID << L" "
                     << pe.szExeFile << std::endl;*/
             }
        } while (Process32NextW(snapshot, &pe));

        CloseHandle(snapshot);
        std::cin >> std::ws; //clear the input buffer

    }
    return 0;

}

   




