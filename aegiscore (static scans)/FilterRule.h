#pragma once
#include <string>
#include <cstdint>

enum class FilterType {
    BLOCK_IP,
    BLOCK_PORT,
    BLOCK_IP_PORT
};

struct FilterRule {
    std::string ip;
    uint16_t port;
    FilterType type;
    std::string description;

    FilterRule(const std::string& ipAddr, FilterType t, const std::string& desc)
        : ip(ipAddr), port(0), type(t), description(desc) {
    }

    FilterRule(uint16_t p, FilterType t, const std::string& desc)
        : ip(""), port(p), type(t), description(desc) {
    }

    FilterRule(const std::string& ipAddr, uint16_t p, FilterType t, const std::string& desc)
        : ip(ipAddr), port(p), type(t), description(desc) {
    }
};