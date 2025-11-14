#include "NetworkUtils.h"

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