// WFPEngine.h
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>   // User mode WFP
#include <vector>
#include <string>
#include <memory>
#include "PacketLogger.h"
#include "FilterRule.h"

// Remove GUIDs related to Callouts
// Remove "RedirectClassify" function declaration

class WFPEngine {
public:
    WFPEngine(std::shared_ptr<PacketLogger> logger);
    ~WFPEngine();

    bool Initialize();
    bool Shutdown();

    bool RemoveAllFilters();

    // Basic Blocking Rules (IP/Port)
    bool AddFilter(const FilterRule& rule);

    // NEW: The Redirect Logic
    // Call this when your main loop detects an unsigned process
    bool AddRedirectFilterByProcess(const std::wstring& processPath, UINT16 proxyPort);

private:
    HANDLE engineHandle;
    std::shared_ptr<PacketLogger> logger;
    std::vector<UINT64> filterIds;
    GUID subLayerGUID;
    bool isInitialized;

    bool CreateSubLayer();
    bool AddIPv4Filter(const FilterRule& rule);
};