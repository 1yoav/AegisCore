#pragma once
#include "SQLDatabase.h"
#include <string>
#include <vector>
#include <filesystem>
#include <map>

// Structure to hold extension metadata and security score
struct ChromeExtension {
    std::string id;
    std::string name;
    std::string path;
    double riskScore; // 0.0 to 1.0 (1.0 = Critical)
    std::vector<std::string> riskyPermissions;
    bool isObfuscated;
};

class ExtensionScanner {
public:
    ExtensionScanner(SQLDatabase* db);

    // Main entry: Scans the default Chrome profile for extensions
    void ScanExtensions();

    // Returns the list of flagged extensions for reporting
    std::vector<ChromeExtension> GetFlaggedExtensions();

private:
    SQLDatabase* database;
    std::vector<ChromeExtension> flaggedExtensions;

    // Core logic
    void ProcessExtension(const std::filesystem::path& extPath);

    // Low-dependency JSON parsing helpers (avoids adding heavy external libs)
    std::string ExtractJsonValue(const std::string& jsonContent, const std::string& key);
    std::vector<std::string> ExtractJsonArray(const std::string& jsonContent, const std::string& key);

    // Heuristic Engine
    double CalculateRiskScore(const std::vector<std::string>& permissions, const std::string& contentScripts, const std::filesystem::path& path);
    bool CheckForObfuscation(const std::filesystem::path& path);
};