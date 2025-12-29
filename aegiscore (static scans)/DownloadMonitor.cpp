#include "DownloadMonitor.h"
#include <iostream>
#include <thread>
#include <vector>

void DownloadMonitor::startMonitor()
{
    // 1. Open a handle to the directory we want to watch
    std::wstring dirPath = L"C:\\Users\\Cyber_User\\Downloads";
    
    HANDLE hDir = CreateFileW(
        dirPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, // Required to open a directory
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Error opening directory handle: " << GetLastError() << std::endl;
        return;
    }

    std::cout << "[*] Real-time download monitor started on: " << std::string(dirPath.begin(), dirPath.end()) << std::endl;

    // Buffer to hold the file system events
    // 1024 bytes is usually enough for a batch of short filenames, but 4KB is safer
    const int BUFFER_SIZE = 4096;
    std::vector<BYTE> buffer(BUFFER_SIZE);
    DWORD bytesReturned;

    while (true)
    {
        // 2. This function BLOCKS until an event happens (no CPU usage while waiting)
        BOOL success = ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            BUFFER_SIZE,
            FALSE, // Watch subtree? (FALSE = only this folder, TRUE = all subfolders)
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
            &bytesReturned,
            NULL,
            NULL
        );

        if (!success || bytesReturned == 0) {
            continue; // Retry on failure
        }

        // 3. Iterate over the events in the buffer
        FILE_NOTIFY_INFORMATION* pInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());
        
        do {
            std::wstring fileName(pInfo->FileName, pInfo->FileNameLength / sizeof(wchar_t));
            std::wstring fullPath = dirPath + L"\\" + fileName;
            
            // Handle specific actions
            switch (pInfo->Action) {
                case FILE_ACTION_ADDED:
                case FILE_ACTION_MODIFIED:
                    // Only scan if it's NOT a temp file
                    if (fullPath.find(L".crdownload") == std::string::npos && 
                        fullPath.find(L".tmp") == std::string::npos) 
                    {
                        processFile(fullPath);
                    }
                    break;

                case FILE_ACTION_RENAMED_NEW_NAME:
                    // This is the CRITICAL event for browsers.
                    // They rename "Unconfirmed 1234.crdownload" -> "virus.exe"
                    processFile(fullPath);
                    break;
            }

            // Move to next entry in buffer
            if (pInfo->NextEntryOffset == 0) break;
            pInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>((LPBYTE)pInfo + pInfo->NextEntryOffset);

        } while (true);
    }

    CloseHandle(hDir);
}

void DownloadMonitor::processFile(std::wstring filePath)
{
    // Filter out temp files immediately
    if (filePath.find(L".crdownload") != std::string::npos || 
        filePath.find(L".tmp") != std::string::npos ||
        filePath.find(L".part") != std::string::npos) {
        return;
    }

    // Thread Safety: Check if we are already scanning this file
    {
        std::lock_guard<std::mutex> lock(processingMutex);
        if (filesInProcess.count(filePath)) {
            return; // Already being processed
        }
        filesInProcess.insert(filePath);
    }

    // Launch the scan in a detached thread so we don't block the monitor loop
    std::thread([this, filePath]() {
        
        // Wait a tiny bit for the file handle to be released by the browser
        // (Browsers sometimes rename the file but hold the handle for a few ms)
        int retries = 0;
        while (isFileLocked(filePath) && retries < 10) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            retries++;
        }

        std::wcout << L"[*] New Download Detected: " << filePath << std::endl;
        
        // Call your existing scanner
        // Note: We need to make sure SigScanner::checkSignature is thread safe too!
        // For now, we assume the scanner instance is safe or we create a local one.
        scanner.checkSignature(filePath);

        // Remove from processing set when done
        {
            std::lock_guard<std::mutex> lock(processingMutex);
            filesInProcess.erase(filePath);
        }

    }).detach();
}

bool DownloadMonitor::isFileLocked(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return true; // Use assumption: if we can't open it, it's locked
    }
    CloseHandle(hFile);
    return false;
}