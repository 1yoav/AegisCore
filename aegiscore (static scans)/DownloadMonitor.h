#pragma once
#include "SigScanner.h"
#include "SQLDatabase.h"
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <set>
//#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include "HelperFunctions.h"
#include "CertificateScanner.h"
#include <future>
//#include "TrafficDiverter.h"
#include "NetworkUtils.h"
#include "AVProcess.h"
#include "PipeClient.h"
#include <iostream>
#include <csignal>
#include <filesystem>
#include <cstdlib>
#include "ExtensionScanner.h"


class DownloadMonitor
{
public:
    DownloadMonitor(SQLDatabase* db) : database(db) 
    {
        downloads = GetFolder(FOLDERID_Downloads);
        desktop = GetFolder(FOLDERID_Desktop);
        temp = L"C:\\Windows\\Temp";
    }

    // The main entry point for the monitoring thread
    void startMonitor(std::wstring dir_path);

    bool keepMonitoring = true; //flag to control the monitoring loop, can be set to false for graceful shutdown
    std::wstring downloads;
    std::wstring desktop;
    std::wstring temp;

private:
    SQLDatabase* database;
    SigScanner scanner;

    // Thread safety tools
    std::mutex processingMutex;
    std::set<std::wstring> filesInProcess; // Using set for faster lookups than vector

    // Internal helper to handle the actual scan logic safely
    void processFile(std::wstring filePath);

    // Helper to check if file is currently locked by a browser (still writing)
    bool isFileLocked(const std::wstring& filePath);
};