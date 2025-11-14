#include "PacketLogger.h"
#include <exception>
#include <iostream>
#include <sstream>
#include <ctime>

PacketLogger::PacketLogger(const std::string& filename, bool console)
    : consoleOutput(console) {
    logFile.open(filename, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << filename << std::endl;
    }
    LogInfo("=== WFP Monitor Started ===");
}

PacketLogger::~PacketLogger() {
    LogInfo("=== WFP Monitor Stopped ===");
    if (logFile.is_open()) {
        logFile.close();
    }
}

std::string PacketLogger::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    // ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

void PacketLogger::LogPacket(const PacketLog& log) {
    std::lock_guard<std::mutex> lock(logMutex);

    std::stringstream ss;
    ss << "[" << log.timestamp << "] "
        << "[" << log.action << "] "
        << log.protocol << " "
        << log.srcIP << ":" << log.srcPort << " -> "
        << log.dstIP << ":" << log.dstPort
        << " | PID: " << log.processId
        << " | Reason: " << log.reason;

    std::string logLine = ss.str();

    if (consoleOutput) {
        if (log.action == "BLOCKED") {
            std::cout << "\033[1;31m" << logLine << "\033[0m" << std::endl; // Red
        }
        else {
            std::cout << "\033[1;32m" << logLine << "\033[0m" << std::endl; // Green
        }
    }

    if (logFile.is_open()) {
        logFile << logLine << std::endl;
        logFile.flush();
    }
}

void PacketLogger::LogInfo(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::string logLine = "[" + GetCurrentTimestamp() + "] [INFO] " + message;

    if (consoleOutput) {
        std::cout << logLine << std::endl;
    }
    if (logFile.is_open()) {
        logFile << logLine << std::endl;
        logFile.flush();
    }
}

void PacketLogger::LogError(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::string logLine = "[" + GetCurrentTimestamp() + "] [ERROR] " + message;

    if (consoleOutput) {
        std::cerr << "\033[1;31m" << logLine << "\033[0m" << std::endl;
    }
    if (logFile.is_open()) {
        logFile << logLine << std::endl;
        logFile.flush();
    }
}
