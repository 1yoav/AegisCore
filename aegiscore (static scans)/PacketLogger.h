#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>

struct PacketLog {
    std::string timestamp;
    std::string action;        // "BLOCKED" or "ALLOWED"
    std::string srcIP;
    uint16_t srcPort;
    std::string dstIP;
    uint16_t dstPort;
    std::string protocol;
    std::string reason;
    uint32_t processId;
};

class PacketLogger {
private:
    std::ofstream logFile;
    std::mutex logMutex;
    bool consoleOutput;

    std::string GetCurrentTimestamp();

public:
    PacketLogger(const std::string& filename = "wfp_monitor.log", bool console = true);
    ~PacketLogger();

    void LogPacket(const PacketLog& log);
    void LogInfo(const std::string& message);
    void LogError(const std::string& message);
};
