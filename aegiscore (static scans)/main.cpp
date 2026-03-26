#include "UiCom.h"



namespace fs = std::filesystem;

HANDLE hEvent;

// ???????????????????????????????????????????????????????????
// PATH HELPER FUNCTIONS - Works for both you and your friend!
// ???????????????????????????????????????????????????????????





// ???????????????????????????????????????????????????????????

void terminateProcessByName(const std::wstring& processName) {
    // יצירת Snapshot של כל התהליכים במערכת
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

void killPipelineProcesses() {
    std::cout << "[*] Cleaning up background processes using Win32 API..." << std::endl;

    std::vector<std::wstring> targets = {
        L"MainProcces.exe",
        L"main.exe",
        L"tlscheck2.exe",
        L"isolationForest.exe",
        L"AegisIcon.exe"
    };

    for (const std::wstring& target : targets) {
        terminateProcessByName(target);
    }
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



BOOL WINAPI ConsoleHandler(DWORD dwType) {
    switch (dwType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
        std::cout << "\n[!] Cleanup triggered by Ctrl+C or Closing window..." << std::endl;
        killPipelineProcesses();
        return FALSE;
    }
    return TRUE;
}




int main()
{
    // ?? Guarantee TEMP/TMP exist regardless of token context ?????
    // When launched as SYSTEM via service, these may point to
    // C:\Windows\Temp or be missing entirely — set them explicitly
    EnableDebugPrivilege();
    HANDLE hStopEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\AegisStopEvent");

    char tempBuf[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempBuf))
    {
        _putenv_s("TEMP", tempBuf);
        _putenv_s("TMP", tempBuf);
    }
    else
    {
        _putenv_s("TEMP", "C:\\Windows\\Temp");
        _putenv_s("TMP", "C:\\Windows\\Temp");
    }

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "[-] Could not set control handler" << std::endl;
        return 1;
    }

    // ?? Wrap entire startup so abort() never fires ????????????????
    std::wstring ProjectRoot = GetProjectRoot();
    std::cout << "[*] Project Root: "
        << fs::path(ProjectRoot).string() << std::endl;


    sqlite3* database = nullptr;
    std::string dbPath = GetDatabasePath();
    std::cout << "[*] Database Path: " << dbPath << std::endl;

    SQLDatabase db(database, dbPath.c_str());

    if (!db.open()) {
        std::cerr << "[-] Database failed to open, continuing without it\n";
        // Don't abort — pipe and scanners can still work
    }

    UiCom uiCom(&db);
    std::thread(&UiCom::start, &uiCom).detach();

    std::cout << "[INIT] Initialize signature scanner...\n";
    std::thread([&]() { uiCom.monitor.startMonitor(uiCom.monitor.downloads); }).detach();
    std::thread([&]() { uiCom.monitor.startMonitor(uiCom.monitor.temp); }).detach();
    std::thread([&]() { uiCom.monitor.startMonitor(uiCom.monitor.desktop); }).detach();

    std::vector<std::string> pipeline = 
    {
        "\"" + (fs::path(ProjectRoot) / "deep_analysis" / "dist" / "isolationForest.exe").string() + "\"",
        "\"" + GetMainProccesPath() + "\"",
        "\"" + (fs::path(ProjectRoot) / "deep_analysis" / "dist" / "main.exe").string() + "\"",
        "\"" + (fs::path(ProjectRoot) / "deep_analysis" / "dist" / "tlscheck2.exe").string() + "\"",
        "\"" + (fs::path(ProjectRoot) / "AegisService" / "AegisIcon" / "bin" / "Debug" / "AegisIcon.exe").string() + "\""

    };

    for (const std::string& task : pipeline) {
        std::string command = "start /b \"\" " + task;
        std::system(command.c_str());
    }
    
    while (true)
    {
        Sleep(1000);

    }
    WaitForSingleObject(hStopEvent, INFINITE);
    killPipelineProcesses();
    exit(0);
}