#pragma once
#include <string>
#include <cstdint>

// A structure to hold the information needed to perform security checks 
// and insert data into the PROCESSES database table.
struct Process {
    uint32_t pid;
    std::wstring exePath;        // C:\Path\To\Process.exe (required for WinVerifyTrust)
    std::wstring processName;    // process.exe (required for display)
    std::wstring userName;       // User running the process

    // Results from the security checks (for database insertion)
    std::string hashSHA256;      // Will be filled out by a static scanner (future)
    std::string signedBy;        // The name of the company that signed the executable
    std::string verdict;         // benign, suspicious, or malicious

    // Constructor (example)
    Process(uint32_t id, const std::wstring& path, const std::wstring& name)
        : pid(id), exePath(path), processName(name), verdict("under_review") {
    }
    // default constructor
    Process() : pid(0) {}

};