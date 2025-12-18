#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>
#include <string>
#include <iostream>

bool GetProcessPath(HANDLE hProcess, std::wstring& outPath)
{
    wchar_t buffer[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size))
    {
        outPath = buffer;
        return true;
    }
    return false;
}


bool IsSystemAccount(HANDLE hProcess)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return true;

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);

    PTOKEN_USER user = (PTOKEN_USER)malloc(size);
    if (!GetTokenInformation(hToken, TokenUser, user, size, &size))
    {
        CloseHandle(hToken);
        free(user);
        return true;
    }

    wchar_t name[256], domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;

    LookupAccountSidW(nullptr, user->User.Sid,
        name, &nameLen, domain, &domainLen, &use);

    std::wstring account = name;

    free(user);
    CloseHandle(hToken);

    return (account == L"SYSTEM" ||
        account == L"LOCAL SERVICE" ||
        account == L"NETWORK SERVICE");
}

bool IsSystemPath(const std::wstring& path)
{
    return path.find(L"\\Windows\\") != std::wstring::npos ||
        path.find(L"\\Program Files\\WindowsApps\\") != std::wstring::npos;
}

bool StartedAtBoot(HANDLE hProcess)
{
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
        return true;

    ULARGE_INTEGER create;
    create.LowPart = ftCreate.dwLowDateTime;
    create.HighPart = ftCreate.dwHighDateTime;

    ULONGLONG processStartMs = create.QuadPart / 10000;
    ULONGLONG bootTimeMs = GetTickCount64();

    return (bootTimeMs - processStartMs < 120000); // 2 minutes
}

bool ShouldSkipProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return true;

    //  Privileged account
    if (IsSystemAccount(hProcess))
    {
        CloseHandle(hProcess);
        return true;
    }

    //  System path
    std::wstring path;
    if (!GetProcessPath(hProcess, path) || IsSystemPath(path))
    {
        CloseHandle(hProcess);
        return true;
    }

    //  Boot-time process
    if (StartedAtBoot(hProcess))
    {
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}