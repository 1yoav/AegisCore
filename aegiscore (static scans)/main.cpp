//#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include "SQLDatabase.h"
#include "HelperFunctions.h"
#include "CertificateScanner.h"
#include <future>
//#include "TrafficDiverter.h"
#include "NetworkUtils.h"
#include "AVProcess.h"
#include "PipeClient.h"
#include "SigScanner.h"
#include <iostream>
#include <string>
#include <csignal>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include "DownloadMonitor.h"
#include "ExtensionScanner.h"


namespace fs = std::filesystem;

struct AnalysisTask {
    std::string name;
    std::string command;
    fs::path path;
};

// ???????????????????????????????????????????????????????????
// PATH HELPER FUNCTIONS - Works for both you and your friend!
// ???????????????????????????????????????????????????????????

std::wstring GetExecutableDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    fs::path exePath(path);
    return exePath.parent_path().wstring();
}

std::wstring GetProjectRoot() {
    // From: C:\...\AegisCore\aegiscore (static scans)\x64\Release\MainProcces.exe
    // Go up 3 levels to get to AegisCore root
    fs::path exeDir = GetExecutableDirectory();
    fs::path projectRoot = exeDir.parent_path()  // Remove "Release" or "Debug"
        .parent_path()  // Remove "x64"
        .parent_path(); // Remove "aegiscore (static scans)" or "MainProcces"
    return projectRoot.wstring();
}

std::string GetDatabasePath() {
    fs::path root = GetProjectRoot();
    fs::path dbPath = root / "aegiscore (static scans)" / "dependencies" / "DATABASE";
    return dbPath.string();
}

std::string GetPythonScriptPath(const std::string& scriptName) {
    fs::path root = GetProjectRoot();
    fs::path scriptPath = root / "deep_analysis" / scriptName;
    return scriptPath.string();
}

std::string GetMainProccesPath() {
    fs::path root = GetProjectRoot();

    // Try Debug first, then Release
    std::vector<fs::path> possiblePaths = {
        root / "MainProcces" / "x64" / "Debug" / "MainProcces.exe",
        root / "MainProcces" / "x64" / "Release" / "MainProcces.exe"
    };

    for (const auto& path : possiblePaths) {
        if (fs::exists(path)) {
            return path.string();
        }
    }

    // Fallback - return Debug path (will error later if not found)
    return possiblePaths[0].string();
}

// ???????????????????????????????????????????????????????????

void killPipelineProcesses() {
    std::cout << "[*] Cleaning up background processes..." << std::endl;

    std::vector<std::string> targets = {
        "MainProcces.exe",
        "main.py",
        "tlscheck2.py",
        "isolationForest.py"
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
}

bool executeTask(const AnalysisTask& task) {
    // Construct the full command string
    std::string fullCommand = task.command + " \"" + task.path.string() + "\"";

    // Execute and capture the exit code
    int result = std::system(fullCommand.c_str());

    if (result == 0) {
        return true;
    }
    else {
        return false;
    }
}


int main()
{
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "[-] Could not set control handler" << std::endl;
        return 1;
    }

#pragma warning(suppress : 4996)
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

    // ???????????????????????????????????????????????????????????
    // INITIALIZE WITH RELATIVE PATHS
    // ???????????????????????????????????????????????????????????

    std::cout << "[*] Project Root: " << fs::path(GetProjectRoot()).string() << std::endl;

    // Initialize database with relative path
    sqlite3* database = nullptr;
    std::string dbPath = GetDatabasePath();
    std::cout << "[*] Database Path: " << dbPath << std::endl;
    SQLDatabase db(database, dbPath.c_str());
    db.open();

    // OPEN EXTENSION CHECKS:
    std::cout << "Scanning Chrome extensions for trojans..." << std::endl;
    ExtensionScanner extScanner(&db);
    extScanner.ScanExtensions();

    //OPEN DOWNLOAD SCANNER THREAD
    std::cout << "[Init] Initializing DownloadMonitor..." << std::endl;
    DownloadMonitor monitor(nullptr);

    // Start monitors of common download destinations
    std::wstring downloads = GetFolder(FOLDERID_Downloads);
    std::wstring desktop = GetFolder(FOLDERID_Desktop);
    std::wstring temp = L"C:\\Windows\\Temp";

    std::thread t1([&]() { if (!downloads.empty()) monitor.startMonitor(downloads); });
    std::thread t2([&]() { if (!desktop.empty()) monitor.startMonitor(desktop); });
    std::thread t3([&]() { monitor.startMonitor(temp); });

    CertificateScanner certScanner;

    // ???????????????????????????????????????????????????????????
    // START PIPELINE WITH RELATIVE PATHS
    // ???????????????????????????????????????????????????????????

    std::vector<std::string> pipeline = {
        "python \"" + GetPythonScriptPath("isolationForest.py") + "\"",
        "\"" + GetMainProccesPath() + "\"",
        "python \"" + GetPythonScriptPath("main.py") + "\"",
        "python \"" + GetPythonScriptPath("tlscheck2.py") + "\""
    };

    std::cout << "\n[*] Starting analysis pipeline..." << std::endl;
    for (const std::string& task : pipeline)
    {
        std::cout << "[*] Launching: " << task << std::endl;
        std::string command = "start /b \"\" " + task;
        std::system(command.c_str());
    }

    // Wait for download monitor threads to finish
    if (t1.joinable()) t1.join();
    if (t2.joinable()) t2.join();
    if (t3.joinable()) t3.join();

    return 0;
}