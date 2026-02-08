#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <map>
#include <thread>
#include <atomic>
#include "windivert.h"

struct OriginalDestination {
    uint32_t ip;
    uint16_t port;
};

class TrafficDiverter {
public:
    TrafficDiverter(uint16_t proxyPort);
    ~TrafficDiverter();

    // Start diverting traffic for a specific PID
    bool StartDiverting(uint32_t pid);

    // Stop diverting traffic for a PID
    bool StopDiverting(uint32_t pid);

    // Stop all diversions
    void StopAll();

private:
    uint16_t proxyPort;
    std::map<uint32_t, HANDLE> activeDiversions;  // PID -> WinDivert handle
    std::map<uint32_t, std::thread> divertThreads; // PID -> worker thread
    std::map<std::string, OriginalDestination> connectionMap; // Track original dest
    std::atomic<bool> running;

    // Worker thread that does the actual packet manipulation
    void DivertWorker(uint32_t pid, HANDLE handle);

    // Helper to generate connection key
    std::string MakeConnectionKey(uint32_t srcIP, uint16_t srcPort);
};