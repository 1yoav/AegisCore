#pragma once
#define WIN32_LEAN_AND_MEAN  // exclude rarely used stuff from windows headers
#include <string>

#include <ws2tcpip.h>
#include <windows.h>



class NetworkUtils {
public:
    static UINT32 IPStringToUInt32(const std::string& ip);
    static std::string UInt32ToIPString(UINT32 ip);
    static std::string GetProtocolName(UINT8 protocol);
    static void SendMetadataToPipe(UINT32 pid, const std::string& origIP, UINT16 origPort);
};
