#include "WFPEngine.h"
#include "NetworkUtils.h"
#include <iostream>
#include <vector>

// Required libraries
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib") 

WFPEngine::WFPEngine(std::shared_ptr<PacketLogger> log)
    : engineHandle(NULL), isInitialized(false), logger(log) {
    if (UuidCreate(&subLayerGUID) != RPC_S_OK) {
        ZeroMemory(&subLayerGUID, sizeof(GUID));
    }
}

WFPEngine::~WFPEngine() {
    Shutdown();
}

bool WFPEngine::Initialize() {
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (result != ERROR_SUCCESS) {
        logger->LogError("Failed to open WFP engine: " + std::to_string(result));
        return false;
    }

    if (!CreateSubLayer()) {
        return false;
    }

    isInitialized = true;
    return true;
}

bool WFPEngine::CreateSubLayer() {
    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = subLayerGUID;
    subLayer.displayData.name = (wchar_t*)L"AegisCore AV SubLayer";
    subLayer.flags = 0;
    subLayer.weight = 0xFFFF;

    DWORD result = FwpmSubLayerAdd0(engineHandle, &subLayer, NULL);
    return (result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);
}

// --------------------------------------------------------------------------------
// Standard Blocking Logic (IP/Port)
// --------------------------------------------------------------------------------
bool WFPEngine::AddFilter(const FilterRule& rule) {
    return AddIPv4Filter(rule);
}

bool WFPEngine::AddIPv4Filter(const FilterRule& rule) {
    FWPM_FILTER0 filter = { 0 };
    FWPM_FILTER_CONDITION0 conditions[2] = { 0 };
    UINT32 conditionCount = 0;
    FWP_RANGE0 rangeValue = { };

    filter.subLayerKey = subLayerGUID;
    filter.displayData.name = (wchar_t*)L"AegisCore Block Filter";
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK; // Standard Block

    // 1. IP Condition
    if (rule.type == FilterType::BLOCK_IP || rule.type == FilterType::BLOCK_IP_PORT) {
        conditions[conditionCount].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        if (rule.min_ip == rule.max_ip) {
            conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
            conditions[conditionCount].conditionValue.type = FWP_UINT32;
            conditions[conditionCount].conditionValue.uint32 = rule.min_ip;
        }
        else {
            rangeValue.valueLow.type = FWP_UINT32;
            rangeValue.valueLow.uint32 = rule.min_ip;
            rangeValue.valueHigh.type = FWP_UINT32;
            rangeValue.valueHigh.uint32 = rule.max_ip;
            conditions[conditionCount].matchType = FWP_MATCH_RANGE;
            conditions[conditionCount].conditionValue.type = FWP_RANGE_TYPE;
            conditions[conditionCount].conditionValue.rangeValue = &rangeValue;
        }
        conditionCount++;
    }

    // 2. Port Condition
    if ((rule.type == FilterType::BLOCK_PORT || rule.type == FilterType::BLOCK_IP_PORT) && rule.port > 0) {
        conditions[conditionCount].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
        conditions[conditionCount].conditionValue.type = FWP_UINT16;
        conditions[conditionCount].conditionValue.uint16 = rule.port;
        conditionCount++;
    }

    filter.numFilterConditions = conditionCount;
    if (conditionCount > 0) filter.filterCondition = conditions;

    UINT64 filterId;
    DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        filterIds.push_back(filterId);
        return true;
    }
    return false;
}

bool WFPEngine::AddRedirectFilterByProcess(const std::wstring& processPath, UINT16 proxyPort) {
    if (!isInitialized) return false;

    FWPM_FILTER0 filter = { 0 };
    FWPM_FILTER_CONDITION0 condition = { 0 };
    UINT64 filterId = 0;

    // 1. Convert process path to AppID
    FWP_BYTE_BLOB* appID = nullptr;
    DWORD result = FwpmGetAppIdFromFileName0(processPath.c_str(), &appID);

    if (result != ERROR_SUCCESS || appID == nullptr) {
        logger->LogError("AppID Conversion Failed: " + std::to_string(result));
        return false;
    }

    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appID;

    filter.subLayerKey = subLayerGUID;
    filter.displayData.name = (wchar_t*)L"AegisCore Trap Filter";
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;

    // add the filter
    result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

    // free memeory
    FwpmFreeMemory0((void**)&appID);

    if (result == ERROR_SUCCESS) {
        filterIds.push_back(filterId);
        std::string pathStr(processPath.begin(), processPath.end());
        logger->LogInfo("TRAP ACTIVATED: Blocked suspicious process: " + pathStr);
        return true;
    }

    logger->LogError("Failed to add filter: " + std::to_string(result));
    return false;
}

bool WFPEngine::RemoveAllFilters() {
    for (UINT64 filterId : filterIds) {
        FwpmFilterDeleteById0(engineHandle, filterId);
    }
    filterIds.clear();
    return true;
}

bool WFPEngine::Shutdown() {
    if (isInitialized) {
        RemoveAllFilters();
        if (engineHandle) FwpmEngineClose0(engineHandle);
        isInitialized = false;
    }
    return true;
}