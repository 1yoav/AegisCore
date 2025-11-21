#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include <stdexcept>

// ip definition
struct IpRange {
    uint32_t start;
    uint32_t end;
};

uint32_t ipStringToInt(const std::string& ipStr) {
    std::istringstream ss(ipStr);
    uint32_t a, b, c, d;
    char dot1, dot2, dot3;
    if (!(ss >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d)) {
        throw std::invalid_argument("Invalid IP format: " + ipStr);
    }
    if (dot1 != '.' || dot2 != '.' || dot3 != '.') {
        throw std::invalid_argument("Invalid IP format: " + ipStr);
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// Convert CIDR to start and end integer IP
IpRange cidrToRange(const std::string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR: " + cidr);
    }

    std::string ipStr = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));

    if (prefix < 0 || prefix > 32) {
        throw std::invalid_argument("Invalid CIDR prefix: " + std::to_string(prefix));
    }

    uint32_t ip = ipStringToInt(ipStr);

    uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    uint32_t start = ip & mask;
    uint32_t end = start | (~mask);

    return { start, end };
}

#pragma once