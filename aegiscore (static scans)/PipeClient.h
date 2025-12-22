#pragma once
#include <windows.h>
#include <string>

class PipeClient {
public:
    // sewds oneway alert python
    static bool SendAlert(uint32_t pid, const std::string& processName, const std::string& destIP, uint16_t destPort);
};