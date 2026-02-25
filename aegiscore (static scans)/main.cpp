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

//int main() {
//    // Data as requested
//    uint32_t pid = 19860;
//    std::string processName = "chrome.exe";
//    std::string destIP = "192.168.1.50"; // Example destination IP
//    uint16_t destPort = 443;             // Example destination port
//
//    std::cout << "[*] Sending alert to Python analysis system..." << std::endl;
//    std::cout << "[*] Target: " << processName << " (PID: " << pid << ")" << std::endl;
//
//    // Call the static function from your PipeClient.h
//    bool success = PipeClient::SendAlert(pid, processName, destIP, destPort);
//
//    if (success) {
//        std::cout << "[+] Alert sent successfully!" << std::endl;
//    }
//    else {
//        std::cerr << "[-] Failed to send alert. Is the Python driver_ctx listening?" << std::endl;
//        return 1;
//    }
//
//    return 0;
//}



void killPipelineProcesses() {
    std::cout << "[*] Cleaning up background processes..." << std::endl;

    // /F = Force, /IM = Image Name, /T = Kill child processes too
    // 2>nul redirects errors to nothing (so it stays quiet if the process isn't running)
    std::system("taskkill /F /IM \"MainProcces.exe\" /T >nul 2>&1");
    std::system("wmic process where \"CommandLine like '%aegiscore-av%'\" call terminate >nul 2>&1");
}

BOOL WINAPI ConsoleHandler(DWORD dwType) {
    switch (dwType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
        std::cout << "\n[!] Cleanup triggered by Ctrl+C or Closing window..." << std::endl;

        killPipelineProcesses();


        return TRUE;
    default:
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
   /* std::cout << "==================================" << std::endl;
    std::cout << "  AegisCore upgraded Commander" << std::endl;
    std::cout << "  WFP + Signature-Based Monitor" << std::endl;
    std::cout << "==================================" << std::endl;*/

    #pragma warning(suppress : 4996) // supress  c++17 or later conversion warning for the following line
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter; // create converter

    // init db
    sqlite3* database = nullptr;
    SQLDatabase db(database, "C:/Users/Cyber_User/Documents/AegisCore/aegiscore (static scans)/dependencies/DATABASE");
    db.open();

    // OPEN EXTENSION CHECKCS:
    std::cout << "Scanning Chrome extensions for trojans..." << std::endl;
    ExtensionScanner extScanner(&db);
    extScanner.ScanExtensions();

    //std::vector<ChromeExtension> flagged = extScanner.GetFlaggedExtensions();
    //if (!flagged.empty()) {
    //    std::cout << "[!] FOUND " << flagged.size() << " MALICIOUS EXTENSIONS!" << std::endl;
    //    for (const auto& ext : flagged) {
    //        // Optional: Send to Python backend via PipeClient
    //        PipeClient::SendAlert(0, "CHROME_EXT_" + ext.name, "0.0.0.0", 0);
    //    }
    //}
    //else {
    //    std::cout << "[+] Chrome extensions look clean." << std::endl;
    //}

    //OPEN DOWNLOAD SCANNER THREAD
    std::cout << "[Init] Initializing DownloadMonitor..." << std::endl;
    DownloadMonitor monitor(nullptr);

    // 2. Start the monitors of common download destinations in a separate thread
    std::wstring downloads = GetFolder(FOLDERID_Downloads);
    std::wstring desktop = GetFolder(FOLDERID_Desktop);
    std::wstring temp = L"C:\\Windows\\Temp"; // Or get User Temp

    // 1. Start threads (using joinable check)
    std::thread t1([&]() { if (!downloads.empty()) monitor.startMonitor(downloads); });
    std::thread t2([&]() { if (!desktop.empty()) monitor.startMonitor(desktop); });
    std::thread t3([&]() { monitor.startMonitor(temp); });


    //auto logger = std::make_shared<PacketLogger>("wfp_monitor.log", true); // init packet logger
    //WFPEngine wfpEngine(logger);
    CertificateScanner certScanner;

    //*********************************************
    //*****for now not working because the wfp ****
    //*********************************************

    //TrafficDiverter diverter(8080); // diverter

    //if (!wfpEngine.Initialize()) {
    //    logger->LogError("Failed to initialize WFP engine. Run as Administrator!");
    //    return 1;
    //}

    //// 3. Load Static & Database Rules
    //std::vector<FilterRule> rules = {FilterRule(69, FilterType::REDIRECT_PORT, "Block TFTP")}; // temporary test rule

    //std::vector<FilterRule> dbRules = db.getC2Rules();
    //rules.insert(rules.end(), dbRules.begin(), dbRules.end());

    //for (const auto& rule : rules) {
    //    wfpEngine.AddFilter(rule);
    //}



    //**************************************************************
    //*****for now not use this because a lot of false positives****
    //**************************************************************


    //std::cout << "\n[*] Active Monitoring Started. Press Ctrl+C to stop." << std::endl;
    //bool running = true;

    //std::set<uint32_t> scannedPids; // track PIDs weve already checked

    //while (running) {
    //std::vector<Process> currentProcesses = NetworkUtils::GetRunningProcesses();

    //for (auto& process : currentProcesses) {
    //    if (process.pid < 100) continue;

    //    if (scannedPids.find(process.pid) == scannedPids.end()) {
    //        bool isTrusted = certScanner.checkSignature(process);

    //        if (!isTrusted) {

    //            #pragma warning(suppress : 4996) // supress  c++17 or later conversion warning for the following line
    //            std::string narrowPath = converter.to_bytes(process.exePath);
    //            std::cout << "[!] ALERT: Unsigned process: " << narrowPath << std::endl;
    //            PipeClient::SendAlert(process.pid, narrowPath.c_str(), "0.0.0.0", 0);
    //        }

    //        scannedPids.insert(process.pid);
    //    }
    //}
    //    // wait a few seconds before rescanning
    //    std::this_thread::sleep_for(std::chrono::seconds(2));
    //}

    //std::cout << "[!] Shutting down..." << std::endl;
    //wfpEngine.Shutdown();
    // monitor.stopMonitor(); // Make sure this sets an atomic 'keepRunning = false'
    const fs::path baseDir = "C:/Users/Cyber_User/Desktop/magshimim/aegiscore-av";

    std::vector<std::string> pipeline = {
        "\"C:/Users/Cyber_User/Desktop/magshimim/aegiscore-av/MainProcces/x64/Debug/MainProcces.exe\"",
        "python \"C:/Users/Cyber_User/Desktop/magshimim/aegiscore-av/deep_analysis/main.py\"",
        "python \"C:/Users/Cyber_User/Desktop/magshimim/aegiscore-av/deep_analysis/tlscheck2.py\""
    };

    for (const std::string& task : pipeline)
    {
        std::string command = "start /b \"\" " + task;

        std::system(command.c_str());
    }

    
    

    

	//wait for sigScan threads to finish before exiting
    if (t1.joinable()) t1.join();
    if (t2.joinable()) t2.join();
    if (t3.joinable()) t3.join();
    return 0;
}
