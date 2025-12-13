#pragma once

#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include "PacketLogger.h"
#include "FilterRule.h"
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <fwpstypes.h>
#include <vector>
#include <memory>
#include <combaseapi.h>
#include <guiddef.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "fwpuclnt.lib")

// 1. Generate a unique GUID for your Redirection Callout
// {8A6D4E8C-47E1-4F12-9B4F-1F7B4C9E8122}
const GUID REDIRECT_CALLOUT_GUID =
{ 0x8a6d4e8c, 0x47e1, 0x4f12, { 0x9b, 0x4f, 0x1f, 0x7b, 0x4c, 0x9e, 0x81, 0x22 } };
class WFPEngine {
public:
    WFPEngine(std::shared_ptr<PacketLogger> logger);
    ~WFPEngine();

    bool Initialize();
    bool AddFilter(const FilterRule& rule);
    bool RemoveAllFilters();
    void Shutdown();

private:
    HANDLE engineHandle;
    GUID subLayerGUID;
    std::vector<UINT64> filterIds;
    std::shared_ptr<PacketLogger> logger;
    bool isInitialized;

    // 2. The Callout "Classify" function. 
    // This is the function Windows calls when a packet matches your redirection rule.
    static void WINAPI RedirectClassify(
        const FWPS_INCOMING_VALUES0* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0* inMetadata,
        void* layerData,
        const void* classifyContext,
        const FWPS_FILTER0* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0* classifyOut
    );

    // 3. Registration helper
    DWORD RegisterCallout();

    bool CreateSubLayer();
    bool AddIPv4Filter(const FilterRule& rule);
};
