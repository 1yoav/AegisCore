#pragma once

#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include "PacketLogger.h"
#include "FilterRule.h"
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <vector>
#include <memory>
#include <combaseapi.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "fwpuclnt.lib")

class WFPEngine {
private:
    HANDLE engineHandle;
    GUID subLayerGUID;
    std::vector<UINT64> filterIds;
    std::shared_ptr<PacketLogger> logger;
    bool isInitialized;

    bool CreateSubLayer();
    bool AddIPv4Filter(const FilterRule& rule);

public:
    WFPEngine(std::shared_ptr<PacketLogger> log);
    ~WFPEngine();

    bool Initialize();
    bool AddFilter(const FilterRule& rule);
    bool RemoveAllFilters();
    void Shutdown();
};