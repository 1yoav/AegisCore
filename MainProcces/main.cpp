#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <iostream>
#include "pipe.h"
#include <string>
#include <vector>
#include <thread>
#include <fcntl.h>
#include "programsValidation.h"

size_t pathLen;
const char* dllPath;

void log(const wchar_t* msg)
{
    wchar_t buffer[512];
    swprintf_s(buffer, 512, L"%s\n", msg);
    OutputDebugStringW(buffer);
}



bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    bool result = (GetLastError() == ERROR_SUCCESS);

    CloseHandle(hToken);
    return result;
}


int injectHooking(HANDLE hProcess)
{
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory)
    {
        //std::cout << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        return 1;
    }
    // Write the DLL path into the target process memory
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, pathLen, NULL))
    {
        //std::cout << "Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return 1;
    }
    // Get the address of LoadLibraryA
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        //std::cout << "Failed to get LoadLibraryA address. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
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
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return 1;
    }


    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);

    // Cleanup
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

    return 0;
}


    





bool IsExcluded(const wchar_t* exeName) 
{
    static const std::vector<std::wstring> whiteList = {
        L"devenv.exe",
        L"aegiscore (static scans).exe",
        L"msmpeng.exe" // 
    };

    for (const auto& excluded : whiteList) {
        if (_wcsicmp(exeName, excluded.c_str()) == 0) {
            return true;
        }
        
    }

    return false;
}


bool IsDllLoadedInRemoteProcess(HANDLE hProcess) 
{
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        int numModules = cbNeeded / sizeof(HMODULE);

        for (int i = 0; i < numModules; i++) {
            char szModName[MAX_PATH];

            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                if (_stricmp(szModName, "hooking2.dll") == 0)
                {
                    return true; 
                }
            }
        }
    }
    return false;
}


int main() 
{
    dllPath = "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\hooking2\\x64\\Debug\\hooking2.dll";
    pathLen = strlen(dllPath) + 1;

    std::vector<int> injectedProcces;

    std::thread pipe([]() { createPipe((wchar_t*)L"\\\\.\\pipe\\my_pipe"); });
    pipe.detach();
    Sleep(2000);

    EnableDebugPrivilege();

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    try
    {
        while (true)
        {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (hSnapshot == INVALID_HANDLE_VALUE) {
                std::cerr << L"Failed to create snapshot. Error: " << GetLastError() << std::endl;
                Sleep(5000);
                continue;
            }

            if (Process32FirstW(hSnapshot, &pe))
            {
                do
                {
                    /*if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                        std::wcout << L"FOUND EXPLORER! PID: " << pe.th32ProcessID << std::endl;
                    }*/

                    DWORD currentPid = GetCurrentProcessId();

                    if (pe.th32ProcessID != currentPid && !IsExcluded(pe.szExeFile))
                    {
                        
                        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);

                        if (hProc)
                        {
                            if (!IsDllLoadedInRemoteProcess(hProc)) //if the dll noy yet loaded
                            {
                                std::wcout << L"[Allowed] PID: " << pe.th32ProcessID
                                    << L"\t Name: " << pe.szExeFile << std::endl;
                                injectHooking(hProc);
                            }
                            CloseHandle(hProc);
                        }
                    }

                } while (Process32NextW(hSnapshot, &pe));
            }

            CloseHandle(hSnapshot);
            Sleep(1000);


        }
    }
    catch (const std::exception&)
    {
		std::cout << "An error occurred: " << GetLastError() << std::endl;
    }
    

    return 0;
}
   




