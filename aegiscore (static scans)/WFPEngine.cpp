#include "WFPEngine.h"
#include "NetworkUtils.h"

WFPEngine::WFPEngine(std::shared_ptr<PacketLogger> log)
    : engineHandle(NULL), isInitialized(false), logger(log) {
    CoCreateGuid(&subLayerGUID);
}

WFPEngine::~WFPEngine() {
    Shutdown();
}

bool WFPEngine::Initialize() {
    DWORD result = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL,
        &engineHandle
    );

    if (result != ERROR_SUCCESS) {
        logger->LogError("Failed to open WFP engine. Error: " + std::to_string(result));
        return false;
    }

    logger->LogInfo("WFP engine opened successfully");

    if (!CreateSubLayer()) {
        FwpmEngineClose0(engineHandle);
        engineHandle = NULL;
        return false;
    }

    isInitialized = true;
    return true;
}

bool WFPEngine::CreateSubLayer() {
    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = subLayerGUID;
    subLayer.displayData.name = (wchar_t*)L"Antivirus Network Monitor";
    subLayer.displayData.description = (wchar_t*)L"Passive network monitoring for antivirus";
    subLayer.flags = 0;
    subLayer.weight = 0xFFFF; // High priority

    DWORD result = FwpmSubLayerAdd0(engineHandle, &subLayer, NULL);

    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        logger->LogError("Failed to create sublayer. Error: " + std::to_string(result));
        return false;
    }

    logger->LogInfo("WFP sublayer created successfully");
    return true;
}

bool WFPEngine::AddFilter(const FilterRule& rule) {
    return AddIPv4Filter(rule);
}

bool WFPEngine::AddIPv4Filter(const FilterRule& rule) {
    FWPM_FILTER0 filter = { 0 };
    FWPM_FILTER_CONDITION0 conditions[2] = { 0 };
    UINT32 conditionCount = 0;

    // Set filter metadata
    filter.subLayerKey = subLayerGUID;
    filter.displayData.name = (wchar_t*)L"AV Network Filter";
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.action.type = FWP_ACTION_BLOCK;

    // Choose layer based on filter type
    if (rule.type == FilterType::BLOCK_IP || rule.type == FilterType::BLOCK_IP_PORT) {
        // Outbound IPv4 layer
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

        // Add IP condition
        conditions[conditionCount].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
        conditions[conditionCount].conditionValue.type = FWP_UINT32;
        conditions[conditionCount].conditionValue.uint32 = NetworkUtils::IPStringToUInt32(rule.ip);
        conditionCount++;
    }

    if (rule.type == FilterType::BLOCK_PORT || rule.type == FilterType::BLOCK_IP_PORT) {
        // Add port condition
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

        conditions[conditionCount].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
        conditions[conditionCount].conditionValue.type = FWP_UINT16;
        conditions[conditionCount].conditionValue.uint16 = rule.port;
        conditionCount++;
    }

    filter.numFilterConditions = conditionCount;
    filter.filterCondition = conditions;

    UINT64 filterId;
    DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

    if (result != ERROR_SUCCESS) {
        logger->LogError("Failed to add filter: " + rule.description +
            ". Error: " + std::to_string(result));
        return false;
    }

    filterIds.push_back(filterId);
    logger->LogInfo("Filter added: " + rule.description);
    return true;
}

bool WFPEngine::RemoveAllFilters() {
    for (UINT64 filterId : filterIds) {
        FwpmFilterDeleteById0(engineHandle, filterId);
    }
    filterIds.clear();
    logger->LogInfo("All filters removed");
    return true;
}

void WFPEngine::Shutdown() {
    if (isInitialized) {
        RemoveAllFilters();

        if (engineHandle) {
            FwpmEngineClose0(engineHandle);
            engineHandle = NULL;
        }

        logger->LogInfo("WFP engine shut down");
        isInitialized = false;
    }
}