#include "NetworkUtils.h"
#include <vector>

#pragma comment(lib, "ws2_32.lib")

UINT32 NetworkUtils::IPStringToUInt32(const std::string& ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return ntohl(addr.s_addr);
}

std::string NetworkUtils::UInt32ToIPString(UINT32 ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
    return std::string(buffer);
}

std::string NetworkUtils::GetProtocolName(UINT8 protocol) {
    switch (protocol) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}


void NetworkUtils::SendMetadataToPipe(UINT32 pid, const std::string& origIP, UINT16 origPort) {
    // 1. Format Data as JSON
    std::string jsonPayload = "{ \"pid\": " + std::to_string(pid) +
        ", \"orig_ip\": \"" + origIP + "\"" +
        ", \"orig_port\": " + std::to_string(origPort) + " }";

    // 2. Open the Pipe
    HANDLE hPipe = CreateFileA(
        "\\\\.\\pipe\\AVDeepScanPipe",
        GENERIC_WRITE,
        0,              // No sharing
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        // Pipe might be busy or Python script isn't running
        return;
    }

    // 3. Write Data
    DWORD bytesWritten;
    WriteFile(hPipe, jsonPayload.c_str(), jsonPayload.size(), &bytesWritten, NULL);

    // 4. Close
    CloseHandle(hPipe);
}


std::vector<Process> NetworkUtils::GetRunningProcesses() {
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