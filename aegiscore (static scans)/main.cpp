#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include "SQLDatabase.h"
#include "HelperFunctions.h"
#include "CertificateScanner.h"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <vector>

int main() {
    std::cout << "==================================" << std::endl;
    std::cout << "  WFP Network Packet Scanner" << std::endl;
    std::cout << "  Antivirus Network Monitor" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << std::endl;

    std::cout << "Initializing databse...\n";

    sqlite3* database = nullptr;
    SQLDatabase db(database, "C:/Users/Cyber_User/Documents/AegisCore/aegiscore (static scans)/dependencies/DATABASE");
    db.open();


    // Initialize logger
    auto logger = std::make_shared<PacketLogger>("wfp_monitor.log", true);

    // Initialize WFP engine
    WFPEngine wfpEngine(logger);

    if (!wfpEngine.Initialize()) {
        logger->LogError("Failed to initialize WFP engine. Run as Administrator!");
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Add filters
    logger->LogInfo("Adding network filters...");

    // static filter rules added here
    std::vector<FilterRule> rules = {
        // block google dns ip for testing
        FilterRule("8.8.8.8", FilterType::BLOCK_IP, "Block Google DNS"),
        FilterRule("8.8.4.4", FilterType::BLOCK_IP, "Block Google DNS Secondary"),

        
        // NEW REDIRECTION/PROXY RULES
        
        // Redirect if destination port is suspicious
        FilterRule(69, FilterType::REDIRECT_PORT, "Block TFTP (port 69)"),
        FilterRule(4444, FilterType::REDIRECT_PORT, "Redirect Suspicious Cryptomining Port 4444 to Proxy"),
        FilterRule(3333, FilterType::REDIRECT_PORT, "Redirect Suspicious Cryptomining Port 3333 to Proxy"),

        FilterRule(0, FilterType::REDIRECT_UNSIGNED, "Redirect All Unsigned Processes to Proxy")
        // ... other static rules ...
    };

    // 2. Fetch Dynamic Rules from DB
    std::cout << "Loading malicious CIDR ranges from database...\n";
    std::vector<FilterRule> dbRules = db.getC2Rules();

    // 3. Merge vectors
    // This adds everything from dbRules to the end of rules
    rules.insert(rules.end(), dbRules.begin(), dbRules.end());

    std::cout << "Total Active Rules: " << rules.size() << "\n";

    for (const auto& rule : rules) {
        wfpEngine.AddFilter(rule);
    }

    std::cout << "\n==================================" << std::endl;
    std::cout << "Filters Active:" << std::endl;
    std::cout << "  - Blocking: 8.8.8.8, 8.8.4.4" << std::endl;
    std::cout << "  - Blocking ports: 69, 3333, 4444, 9999" << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "\nMonitoring network traffic..." << std::endl;
    std::cout << "Try: ping 8.8.8.8 or browse to a site using port 69" << std::endl;
    std::cout << "\nPress Enter to stop monitoring..." << std::endl;

    // Wait for user input
    std::cin.get();

    // Cleanup
    logger->LogInfo("Shutting down...");
    wfpEngine.Shutdown();

    std::cout << "\nMonitoring stopped. Check wfp_monitor.log for details." << std::endl;
    return 0;
}







//void testFile(const std::wstring& path, const std::wstring& name) {
//    std::wcout << L"\n--- Testing: " << name << L" ---" << std::endl;
//    std::wcout << L"Path: " << path << std::endl;
//
//    // 1. Create the process structure (Mocking what the AV would do on launch)
//    // We use a dummy PID (1234) since we are just testing static files on disk
//    Process proc(1234, path, name);
//
//    // 2. Initialize the Scanner
//    CertificateScanner scanner;
//
//    // 3. Run the Check
//    std::cout << "[*] Running WinVerifyTrust..." << std::endl;
//    bool isTrusted = scanner.checkSignature(proc);
//
//    // 4. Output Results
//    std::cout << "Verdict: " << boolToString(isTrusted) << std::endl;
//
//    if (isTrusted) {
//        std::cout << "Signed By: " << proc.signedBy << std::endl;
//    }
//    else {
//        std::cout << "Reason: Signature missing, invalid, or untrusted root." << std::endl;
//    }
//}
//
//int main() {
//    std::cout << "============================================" << std::endl;
//    std::cout << "   Certificate Scanner Unit Test" << std::endl;
//    std::cout << "============================================" << std::endl;
//
//    // TEST CASE 1: A file guaranteed to be signed (Notepad)
//    // Note: We use L"" for wide strings because AVProcess.exePath is std::wstring
//    WCHAR systemPath[MAX_PATH];
//    GetSystemDirectoryW(systemPath, MAX_PATH);
//
//    // Attempting explorer.exe which is often consistently signed
//    std::wstring validPath = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
//
//    testFile(validPath, L"chrome.exe");
//
//    // TEST CASE 2: A file guaranteed to be unsigned (This test program itself!)
//    // We get the path of the currently running executable
//    WCHAR selfPath[MAX_PATH];
//    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
//
//    testFile(selfPath, L"Unsigned_Test_App.exe");
//
//    std::cout << "\n============================================" << std::endl;
//    std::cout << "Press Enter to exit...";
//    std::cin.get();
//
//    return 0;
//}
