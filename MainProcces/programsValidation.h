#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>

#include <string>
#include <vector>
#include <iostream>

//
// ====================== Helpers ======================
//

// Get full process path
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

// Check if process runs as SYSTEM / service accounts
bool IsSystemAccount(HANDLE hProcess)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return true; // treat as sensitive

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);

    PTOKEN_USER user = (PTOKEN_USER)malloc(size);
    if (!user)
    {
        CloseHandle(hToken);
        return true;
    }

    if (!GetTokenInformation(hToken, TokenUser, user, size, &size))
    {
        CloseHandle(hToken);
        free(user);
        return true;
    }

    wchar_t name[256] = { 0 };
    wchar_t domain[256] = { 0 };
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;

    LookupAccountSidW(
        nullptr,
        user->User.Sid,
        name, &nameLen,
        domain, &domainLen,
        &use
    );

    std::wstring account = name;

    free(user);
    CloseHandle(hToken);

    return (
        account == L"SYSTEM" ||
        account == L"LOCAL SERVICE" ||
        account == L"NETWORK SERVICE"
        );
}

// Windows / protected paths
bool IsWindowsPath(const std::wstring& path)
{
    return (
        path.find(L"\\Windows\\") != std::wstring::npos ||
        path.find(L"\\Program Files\\WindowsApps\\") != std::wstring::npos
        );
}

// Boot-time signal (NOT a hard decision)
bool StartedAtBoot(HANDLE hProcess)
{
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
        return false;

    ULARGE_INTEGER create;
    create.LowPart = ftCreate.dwLowDateTime;
    create.HighPart = ftCreate.dwHighDateTime;

    ULONGLONG processStartMs = create.QuadPart / 10000;
    ULONGLONG uptimeMs = GetTickCount64();

    // 3 minutes window
    return (uptimeMs - processStartMs < 180000);
}

// Known LOLBins (extend as needed)
bool IsKnownLOLBin(const std::wstring& exeName)
{
    static const std::vector<std::wstring> lolbins = {
        L"powershell.exe",
        L"cmd.exe",
        L"mshta.exe",
        L"rundll32.exe",
        L"regsvr32.exe",
        L"wmic.exe"
    };

    for (const auto& bin : lolbins)
    {
        if (_wcsicmp(bin.c_str(), exeName.c_str()) == 0)
            return true;
    }
    return false;
}

//
// ====================== Risk Engine ======================
//

int CalculateProcessRisk(DWORD pid)
{
    int score = 0;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return -100; // cannot inspect -> do not touch

    std::wstring path;
    if (GetProcessPath(hProcess, path))
    {
        if (IsWindowsPath(path))
            score -= 40;

        size_t pos = path.find_last_of(L"\\");
        if (pos != std::wstring::npos)
        {
            std::wstring exeName = path.substr(pos + 1);
            if (IsKnownLOLBin(exeName))
                score += 50;
        }
    }
    else
    {
        score -= 20; // unknown path is risky but opaque
    }

    if (IsSystemAccount(hProcess))
        score -= 100;
    else
        score += 30;

    if (StartedAtBoot(hProcess))
        score -= 20;

    CloseHandle(hProcess);
    return score;
}

// Final decision: SHOULD WE EVEN CONSIDER HOOKING?
bool ShouldConsiderHooking(DWORD pid)
{

    int risk = CalculateProcessRisk(pid);


    // Tunable threshold
    return (risk >= 30);
}


