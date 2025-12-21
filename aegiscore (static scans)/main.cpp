#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include "SQLDatabase.h"
#include "HelperFunctions.h"
#include "CertificateScanner.h"
#include "TrafficDiverter.h"
#include "NetworkUtils.h" // For SendMetadataToPipe
#include "AVProcess.h"    // For process structures
#include "PipeClient.h"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <vector>
#include <codecvt>
#include <locale>
#include <tlhelp32.h>     // For process enumeration
#include <set>

#include <psapi.h> // You need this for GetModuleFileNameEx

std::vector<Process> GetRunningProcesses() {
    std::vector<Process> processes;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            Process proc;
            proc.pid = pe32.th32ProcessID;

            // 1. Open the process to find its home address
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.pid);
            if (hProcess) {
                wchar_t fullPath[MAX_PATH];
                DWORD size = MAX_PATH;

                // 2. Get the REAL full path
                if (QueryFullProcessImageNameW(hProcess, 0, fullPath, &size)) {
                    proc.exePath = fullPath;
                }
                else {
                    proc.exePath = pe32.szExeFile; // Fallback to name if path fails
                }
                CloseHandle(hProcess);
            }
            else {
                proc.exePath = pe32.szExeFile;
            }

            processes.push_back(proc);
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return processes;
}

int main() {
    std::cout << "==================================" << std::endl;
    std::cout << "  AegisCore upgraded Commander" << std::endl;
    std::cout << "  WFP + Signature-Based Monitor" << std::endl;
    std::cout << "==================================" << std::endl;

    // Create a converter
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;


    // 1. Initialize Database
    sqlite3* database = nullptr;
    SQLDatabase db(database, "C:/Users/Cyber_User/Documents/AegisCore/aegiscore (static scans)/dependencies/DATABASE");
    db.open();

    // 2. Initialize Logger and Engine
    auto logger = std::make_shared<PacketLogger>("wfp_monitor.log", true);
    WFPEngine wfpEngine(logger);
    CertificateScanner certScanner;

    TrafficDiverter diverter(8080); // diverter

    if (!wfpEngine.Initialize()) {
        logger->LogError("Failed to initialize WFP engine. Run as Administrator!");
        return 1;
    }

    // 3. Load Static & Database Rules
    std::vector<FilterRule> rules = {
        FilterRule("8.8.8.8", FilterType::BLOCK_IP, "Block Google DNS"),
        FilterRule(69, FilterType::REDIRECT_PORT, "Block TFTP"),
    };

    std::vector<FilterRule> dbRules = db.getC2Rules();
    rules.insert(rules.end(), dbRules.begin(), dbRules.end());

    for (const auto& rule : rules) {
        wfpEngine.AddFilter(rule);
    }

    // 4. MAIN MONITORING LOOP
    // This is the "upgraded" part that talks to Python
    std::cout << "\n[*] Active Monitoring Started. Press Ctrl+C to stop." << std::endl;
    bool running = true;

    std::set<uint32_t> scannedPids; // Track PIDs we've already checked

    while (running) {
        std::vector<Process> currentProcesses = GetRunningProcesses();

        for (auto& process : currentProcesses) {
            if (process.pid < 100) continue;

            // ONLY scan if we haven't seen this PID before
            if (scannedPids.find(process.pid) == scannedPids.end()) {

                bool isTrusted = certScanner.checkSignature(process);

                if (!isTrusted) {
                    std::wcout << L"[!] Unsigned Process: " << process.exePath << std::endl;
                    // diverter.StartDiverting(process.pid); //FUCK THIS
                    
                    // Convert the wide path to a narrow string
                    std::string narrowPath = converter.to_bytes(process.exePath);
                    bool sent = PipeClient::SendAlert(process.pid, narrowPath.c_str(), "0.0.0.0", 0);
                }

                scannedPids.insert(process.pid); // Mark as done
            }
        }

        // Optional: Periodically clear scannedPids if you want to re-scan
        // For now, let's keep it simple to fix the performance bug.
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    // Cleanup
    wfpEngine.Shutdown();
    return 0;
}