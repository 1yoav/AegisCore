#include "PipeClient.h"
#include <iostream>
#include <regex>
bool PipeClient::SendAlert(uint32_t pid, const std::string& processName, const std::string& destIP, uint16_t destPort) {
    std::cout << "SENDING ALERT\n";
    // 1. ESCAPE THE PATH: Turn single \ into double \\ 
    std::string escapedPath = "";
    for (char c : processName) {
        if (c == '\\') {
            escapedPath += "\\\\";
        }
        else {
            escapedPath += c;
        }
    }

    // 2. Prepare the JSON payload using the escaped path
    std::string jsonPayload = "{ \"pid\": " + std::to_string(pid) +
        ", \"process_name\": \"" + escapedPath + "\"" +
        ", \"orig_ip\": \"" + destIP + "\"" +
        ", \"orig_port\": " + std::to_string(destPort) + " }";
    const char* pipeName = "\\\\.\\pipe\\AVDeepScanPipe";

    // NEW: Wait for the pipe to become available (up to 1 second)
    // This prevents "File Not Found" errors if two alerts happen at once
    if (!WaitNamedPipeA(pipeName, 1000)) {
        return false;
    }
    std::cout << "CREATING PIPE\n";
    HANDLE hPipe = CreateFileA(
        pipeName,
        GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten;
    bool success = WriteFile(hPipe, jsonPayload.c_str(), (DWORD)jsonPayload.size(), &bytesWritten, NULL);

    CloseHandle(hPipe);
    return success;
}