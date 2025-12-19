#pragma once
#include <string>
#include "Ip.h"
#include <cstdint>

enum class FilterType {

    //BLOCKING FILTERS
    BLOCK_IP,
    BLOCK_PORT,
    BLOCK_IP_PORT,

    // REDIRECTION FILTERS (to deep scan)
    REDIRECT_PORT,
    REDIRECT_UNSIGNED,
    REDIRECT_BAD_HOOK

};

struct FilterRule {
    std::string ipStr; // Keep for display/logging
    uint32_t min_ip;   // NEW: For fast range checking
    uint32_t max_ip;   // NEW: For fast range checking
    uint16_t port;
    FilterType type;
    std::string description;
    std::string process_path; // used to know who to send to the deep scan

    // Constructor 1: Single IP String (e.g. "8.8.8.8")
    FilterRule(const std::string& ipAddr, FilterType t, const std::string& desc)
        : ipStr(ipAddr), port(0), type(t), description(desc) {
        // Convert string to int, set min and max to the same value
        uint32_t val = ipStringToInt(ipAddr);
        min_ip = val;
        max_ip = val;
        process_path = "";
    }

    // Constructor 2: Port only
    FilterRule(uint16_t p, FilterType t, const std::string& desc)
        : ipStr(""), min_ip(0), max_ip(0), port(p), type(t), description(desc), process_path("portblock") {
    }

    // Constructor 3: IP String + Port
    FilterRule(const std::string& ipAddr, uint16_t p, FilterType t, const std::string& desc)
        : ipStr(ipAddr), port(p), type(t), description(desc) {
        uint32_t val = ipStringToInt(ipAddr);
        min_ip = val;
        max_ip = val;
        process_path = "";
    }

    // Constructor 4: INTEGER RANGE (For your Database)
    FilterRule(uint32_t start, uint32_t end, FilterType t, const std::string& desc)
        : ipStr("CIDR_RANGE"), min_ip(start), max_ip(end), port(0), type(t), description(desc), process_path("") {
    }
};