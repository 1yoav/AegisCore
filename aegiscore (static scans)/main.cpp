#include "UiCom.h"



namespace fs = std::filesystem;
HANDLE hEvent;

// ???????????????????????????????????????????????????????????
// PATH HELPER FUNCTIONS - Works for both you and your friend!
// ???????????????????????????????????????????????????????????





// ???????????????????????????????????????????????????????????

void killPipelineProcesses() {
    std::cout << "[*] Cleaning up background processes..." << std::endl;

    std::vector<std::string> targets = {
        "MainProcces.exe",
        "main.exe",
        "tlscheck2.exe",
        "isolationForest.exe"
    };

    for (const std::string& target : targets) {
        std::string command = "powershell -Command \"Get-CimInstance Win32_Process | "
            "Where-Object { $_.CommandLine -like '*" + target + "*' } | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }\"";

        std::system(command.c_str());
    }
    return;
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
    std::ofstream bootLog("C:\\aegis_boot.txt");
    bootLog << "Main started" << std::endl;
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
    
    bootLog << "entered try and catch" << std::endl;
    // ?? Wrap entire startup so abort() never fires ????????????????
    try
    {
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
        bootLog << "uicom constructor..." << std::endl;
        UiCom uiCom(&db);
        std::thread uiThread(&UiCom::start, &uiCom);

        std::cout << "[INIT] Initialize signature scanner...\n";

        std::thread([&]() {
            try { uiCom.monitor.startMonitor(uiCom.monitor.downloads); }
            catch (...) { std::ofstream l("C:\\Windows\\Temp\\aegis_monitor.txt"); l << "downloads monitor threw\n"; }
            }).detach();
        std::thread([&]() {
            try { uiCom.monitor.startMonitor(uiCom.monitor.temp); }
            catch (...) { std::ofstream l("C:\\Windows\\Temp\\aegis_monitor.txt", std::ios::app); l << "temp monitor threw\n"; }
            }).detach();
        std::thread([&]() {
            try { uiCom.monitor.startMonitor(uiCom.monitor.desktop); }
            catch (...) { std::ofstream l("C:\\Windows\\Temp\\aegis_monitor.txt", std::ios::app); l << "desktop monitor threw\n"; }
            }).detach();

        std::vector<std::string> pipeline = {
            "\"" + (fs::path(ProjectRoot) / "deep_analysis" / "dist" / "isolationForest.exe").string() + "\"",
            "\"" + GetMainProccesPath() + "\"",
            "\"" + (fs::path(ProjectRoot) / "deep_analysis" / "dist" / "main.exe").string() + "\"",
            "\"" + (fs::path(ProjectRoot) / "deep_analysis" / "dist" / "tlscheck2.exe").string() + "\""
        };

        for (const std::string& task : pipeline) {
            std::string command = "start /b \"\" " + task;
            std::system(command.c_str());
        }

        uiThread.join();
    }
    catch (const std::exception& e)
    {
        std::ofstream log("C:\\Windows\\Temp\\aegiscore_crash.txt");
        log << "Exception: " << e.what() << "\n";
        return 1;
    }
    catch (...)
    {
        std::ofstream log("C:\\Windows\\Temp\\aegiscore_crash.txt");
        log << "Unknown exception at startup\n";
        return 1;
    }

    return 0;
}