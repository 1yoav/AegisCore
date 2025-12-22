#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>      // FIRST
#include <ws2tcpip.h>      // SECOND
#include <Windows.h>       // THIRD
#include <string>
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <vector>
#include <codecvt>
#include <locale>
#include <tlhelp32.h>
#include <set>
#include <psapi.h>
#include "AVProcess.h"



class NetworkUtils {
public:
    static UINT32 IPStringToUInt32(const std::string& ip);
    static std::string UInt32ToIPString(UINT32 ip);
    static std::string GetProtocolName(UINT8 protocol);
    static void SendMetadataToPipe(UINT32 pid, const std::string& origIP, UINT16 origPort);
    static std::vector<Process> GetRunningProcesses();
};
