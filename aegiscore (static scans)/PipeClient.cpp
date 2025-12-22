#include "PipeClient.h"
#include <iostream>
#include <regex>
bool PipeClient::SendAlert(uint32_t pid, const std::string& processName, const std::string& destIP, uint16_t destPort) {
    std::cout << "SENDING ALERT\n";
    const char* pipeName = "\\\\.\\pipe\\AVDeepScanPipe";

    // 1. ESCAPE THE PATH: Turn single \ into double \\ so JSON doesn't break
    std::string escapedPath = std::regex_replace(processName, std::regex("\\\\"), "\\\\");

    // 2. Prepare the JSON payload using the now populated escapedPath
    std::string jsonPayload = "{ \"pid\": " + std::to_string(pid) +
        ", \"process_name\": \"" + escapedPath + "\"" +
        ", \"orig_ip\": \"" + destIP + "\"" +
        ", \"orig_port\": " + std::to_string(destPort) + " }";

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
    std::cout << jsonPayload.c_str();
    bool success = WriteFile(hPipe, jsonPayload.c_str(), (DWORD)jsonPayload.size(), &bytesWritten, NULL);

    CloseHandle(hPipe);
    return success;
}