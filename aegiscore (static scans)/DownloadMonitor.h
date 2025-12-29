#pragma once
#include "SigScanner.h"
#include "SQLDatabase.h"
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <set>

class DownloadMonitor
{
public:
    DownloadMonitor(SQLDatabase* db) : database(db) {}

    // The main entry point for the monitoring thread
    void startMonitor();

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