#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <fstream>
#include <filesystem>
#include <shlobj.h>
#include <windows.h>
#include <winsvc.h>

#include "CertificateScanner.h"
#include "SigScanner.h"

namespace fs = std::filesystem;

class SystemScanner
{
public:
    SystemScanner();

    // Entry point — runs all sub-scans in parallel, writes aegis_scan_result.json
    void runFullScan();

private:
    CertificateScanner certScanner;

    // Sub-scanners (each writes to its own local findings vector)
    void scanStartupLocations(std::vector<std::string>& findings, bool& threatFound);
    void scanScheduledTasks(std::vector<std::string>& findings, bool& threatFound);
    void scanInstalledServices(std::vector<std::string>& findings, bool& threatFound);

    // Shared helper: cert + VT check, pipes dirty files to deep analysis
    // Returns true = clean, false = flagged
    bool scanAndFlag(const std::wstring& filePath, const std::string& context,
        std::vector<std::string>& findings);

    // Writes the final JSON result file
    void writeResult(const std::vector<std::string>& findings, bool threatFound);
};