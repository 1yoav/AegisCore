#include "DownloadMonitor.h"
#include <iostream>
#include <thread>
#include <vector>

void DownloadMonitor::startMonitor(std::wstring dir_path)
{
    // 1. Open a handle to the directory we want to watch
    
    
    HANDLE hDir = CreateFileW(
        dir_path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, // Required to open a directory
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        //std::cerr << "[!] Error opening directory handle: " << GetLastError() << std::endl;
        return;
    }

    //std::cout << "[*] Real-time download monitor started on: " << std::string(dir_path.begin(), dir_path.end()) << std::endl;

    // Buffer to hold the file system events
    // 1024 bytes is usually enough for a batch of short filenames, but 4KB is safer
    const int BUFFER_SIZE = 4096;
    std::vector<BYTE> buffer(BUFFER_SIZE);
    DWORD bytesReturned;

    while (keepMonitoring)
    {
        // 2. This function BLOCKS until an event happens (no CPU usage while waiting)
        BOOL success = ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            BUFFER_SIZE,
            TRUE, // Watch subtree? (FALSE = only this folder, TRUE = all subfolders)
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
            std::wstring fullPath = dir_path + L"\\" + fileName;
            


            // Handle specific actions
            switch (pInfo->Action) {
                case FILE_ACTION_ADDED:
                case FILE_ACTION_MODIFIED:
                    // Only scan if it's NOT a temp file or a folder
                    if (fullPath.find(L".crdownload") == std::string::npos && 
                        fullPath.find(L".tmp") == std::string::npos &&
                        std::filesystem::is_directory(fullPath))
                    {
                        processFile(fullPath);
                    }
                    break;

                case FILE_ACTION_RENAMED_NEW_NAME:
                    // if file was renamed from temp to exe (or any other pe), scan it
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
    // 1. FILTER: Ignore known temporary/active download extensions
    // If a file is "Malware.exe.crdownload", we ignore it here.
    // We will catch it later when it is RENAMED to "Malware.exe".
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    if (lowerPath.find(L".crdownload") != std::string::npos ||
        lowerPath.find(L".tmp") != std::string::npos ||
        lowerPath.find(L".part") != std::string::npos) {
        return;
    }

    // 2. DEDUPLICATION (Thread Safety)
    // This prevents multiple threads from "settling" the same file 
    // if the OS sends multiple notifications for one download.
    {
        std::lock_guard<std::mutex> lock(processingMutex);
        if (filesInProcess.count(filePath)) {
            return;
        }
        filesInProcess.insert(filePath);
    }

    // 3. THE PIPELINE THREAD
    std::thread([this, filePath]() {
        uint64_t lastSize = 0;
        int stabilityCount = 0;
        const int REQUIRED_STABILITY = 5; // Must be stable for 5 checks (1 second total)

        //std::wcout << L"[*] Tracking file completion: " << filePath << std::endl;

        // PHASE A: Wait for file to exist and stop growing (Handles Torrents/Large Files)
        while (stabilityCount < REQUIRED_STABILITY) {
            if (std::filesystem::exists(filePath)) {
                std::error_code ec;
                uint64_t currentSize = std::filesystem::file_size(filePath, ec);

                if (!ec && currentSize > 0 && currentSize == lastSize) {
                    stabilityCount++;
                }
                else {
                    stabilityCount = 0;
                    lastSize = currentSize;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        // PHASE B: Wait for the downloader to release the file handle (Handles Chrome Rename)
        // Even if the size is stable, the browser might still be "touching" it.
        int lockRetries = 0;
        while (isFileLocked(filePath) && lockRetries < 20) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            lockRetries++;
        }

        // PHASE C: The Final Scan
        if (std::filesystem::exists(filePath)) {
            //std::wcout << L"[!] Scanning finalized file: " << filePath << std::endl;
            scanner.checkSignature(filePath);
        }

        // 4. CLEANUP: Allow this file to be monitored again in the future
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