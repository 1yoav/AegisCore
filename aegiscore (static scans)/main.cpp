#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include "SQLDatabase.h"
#include "HelperFunctions.h"
#include "CertificateScanner.h"
#include "TrafficDiverter.h"
#include "NetworkUtils.h"
#include "AVProcess.h"
#include "PipeClient.h"
 // You need this for GetModuleFileNameEx


int main() {
    std::cout << "==================================" << std::endl;
    std::cout << "  AegisCore upgraded Commander" << std::endl;
    std::cout << "  WFP + Signature-Based Monitor" << std::endl;
    std::cout << "==================================" << std::endl;

    // Create a converter
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;


    // init db
    sqlite3* database = nullptr;
    SQLDatabase db(database, "C:/Users/Cyber_User/Documents/AegisCore/aegiscore (static scans)/dependencies/DATABASE");
    db.open();

    auto logger = std::make_shared<PacketLogger>("wfp_monitor.log", true); // init packet logger
    WFPEngine wfpEngine(logger);
    CertificateScanner certScanner;

    TrafficDiverter diverter(8080); // diverter

    if (!wfpEngine.Initialize()) {
        logger->LogError("Failed to initialize WFP engine. Run as Administrator!");
        return 1;
    }

    // 3. Load Static & Database Rules
    std::vector<FilterRule> rules = {FilterRule(69, FilterType::REDIRECT_PORT, "Block TFTP")}; // temporary test rule

    std::vector<FilterRule> dbRules = db.getC2Rules();
    rules.insert(rules.end(), dbRules.begin(), dbRules.end());

    for (const auto& rule : rules) {
        wfpEngine.AddFilter(rule);
    }


    std::cout << "\n[*] Active Monitoring Started. Press Ctrl+C to stop." << std::endl;
    bool running = true;

    std::set<uint32_t> scannedPids; // Track PIDs we've already checked

    while (running) {
    std::vector<Process> currentProcesses = NetworkUtils::GetRunningProcesses();

    // Inside main() while loop
    for (auto& process : currentProcesses) {
        if (process.pid < 100) continue;

        if (scannedPids.find(process.pid) == scannedPids.end()) {
            bool isTrusted = certScanner.checkSignature(process);

            if (!isTrusted) {
                // ONLY if both WinVerifyTrust AND our path-fallback fail
                std::string narrowPath = converter.to_bytes(process.exePath);
                std::cout << "[!] ALERT: Unsigned process: " << narrowPath << std::endl;
                PipeClient::SendAlert(process.pid, narrowPath.c_str(), "0.0.0.0", 0);
            }

            scannedPids.insert(process.pid);
        }
    }
        // wait a few seconds before rescanning
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    // exit
    wfpEngine.Shutdown();
    return 0;

    /*bool sent = PipeClient::SendAlert(1544, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "0.0.0.0", 0); one line tester*/ 
}