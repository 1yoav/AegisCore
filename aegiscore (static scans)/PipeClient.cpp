#include "PipeClient.h"
#include <iostream>
#include <regex>
bool PipeClient::SendAlert(uint32_t pid, const std::string& processName, const std::string& destIP, uint16_t destPort) {
    std::cout << "SENDING ALERT JSON PAYLOAD: \n";
    const char* pipeName = "\\\\.\\pipe\\AVDeepScanPipe";

    // replace \ with \\ for python
    std::string escapedPath = std::regex_replace(processName, std::regex("\\\\"), "\\\\");

    // pdate json with correct escape strings
    std::string jsonPayload = "{ \"pid\": " + std::to_string(pid) +
        ", \"process_name\": \"" + escapedPath + "\"" +
        ", \"orig_ip\": \"" + destIP + "\"" +
        ", \"orig_port\": " + std::to_string(destPort) + " }";
    std::cout << jsonPayload << std::endl;

    // wait for the pipe to become available (up to 1 second)
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