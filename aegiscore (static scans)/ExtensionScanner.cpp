#include "ExtensionScanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ShlObj.h> // For getting AppData path

namespace fs = std::filesystem;

ExtensionScanner::ExtensionScanner(SQLDatabase* db) : database(db) {}

void ExtensionScanner::ScanExtensions() {
    // 1. Locate Chrome Extensions Directory (Default Profile)
    PWSTR localAppData = nullptr;
    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) != S_OK) {
        return;
    }

    std::wstring chromePath = std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\Extensions";
    CoTaskMemFree(localAppData);

    if (!fs::exists(chromePath)) {
        return;
    }

    // 2. Iterate through Extension IDs
    for (const auto& entry : fs::directory_iterator(chromePath)) {
        if (entry.is_directory()) {
            // Chrome extensions often have version subfolders (e.g., ID/1.0.0_0/)
            // We need to find the specific version folder containing manifest.json
            for (const auto& versionEntry : fs::directory_iterator(entry.path())) {
                if (versionEntry.is_directory()) {
                    ProcessExtension(versionEntry.path());
                }
            }
        }
    }
}

void ExtensionScanner::ProcessExtension(const fs::path& extPath) {
    fs::path manifestPath = extPath / "manifest.json";
    if (!fs::exists(manifestPath)) return;

    // Read Manifest
    std::ifstream file(manifestPath);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Basic Parsing
    std::string name = ExtractJsonValue(content, "name");
    std::string version = ExtractJsonValue(content, "version");
    std::vector<std::string> permissions = ExtractJsonArray(content, "permissions");

    // Also grab 'host_permissions' (Manifest V3) or optional_permissions
    std::vector<std::string> hostPerms = ExtractJsonArray(content, "host_permissions");
    permissions.insert(permissions.end(), hostPerms.begin(), hostPerms.end());

    // 3. Heuristic Analysis
    double score = CalculateRiskScore(permissions, content, extPath);

    if (score >= 0.7) { // Threshold for "Suspicious"
        ChromeExtension ext;
        ext.id = extPath.parent_path().filename().string();
        ext.name = name.empty() ? ext.id : name;
        ext.path = extPath.string();
        ext.riskScore = score;
        ext.riskyPermissions = permissions;

        // Final check: Look for obfuscation in JS files
        if (CheckForObfuscation(extPath)) {
            std::cout << "IFLE IS OBUSIFICATED";
            ext.riskScore += 0.2; // Increase score if obfuscated
            ext.isObfuscated = true;
        }

        flaggedExtensions.push_back(ext);

        // Log to console immediately
        // std::cout << "[!] SUSPICIOUS EXTENSION: " << ext.name << " (Score: " << ext.riskScore << ")" << std::endl;
        std::cout << "    Path: " << ext.path << std::endl;
    }
}

// --------------------------------------------------------------------------------
// Heuristic Logic: This minimizes False Positives by weighting combinations
// --------------------------------------------------------------------------------
double ExtensionScanner::CalculateRiskScore(const std::vector<std::string>& permissions, const std::string& fullJson, const fs::path& path) {
    double score = 0.0;
    bool hasWebRequest = false;
    bool hasBlocking = false;
    bool hasAllUrls = false;
    bool hasCookies = false;
    bool hasScripting = false;

    // 1. Permission Weights
    for (const auto& p : permissions) {
        if (p.find("webRequest") != std::string::npos) { score += 0.3; hasWebRequest = true; std::cout << "\n\nIFLE HAS WEB REQUESTS\n\nFILE BLOCKS WEB REQUESTS\n\n";}
        if (p.find("webRequestBlocking") != std::string::npos) { score += 0.4; hasBlocking = true; std::cout << "IFLE BLOCKS WEB REQUESTS";}
        if (p.find("cookies") != std::string::npos) { score += 0.3; hasCookies = true; "IFLE BLOCKS WEB REQUESTS"; }
        if (p.find("scripting") != std::string::npos) { score += 0.2; hasScripting = true; }
        if (p.find("<all_urls>") != std::string::npos || p.find("http://*/*") != std::string::npos) {
            score += 0.3;
            hasAllUrls = true;
        }
        if (p.find("tabs") != std::string::npos) score += 0.1;
    }

    // 2. Combination Logic (The "Trojan" Pattern)
    // Banking trojans need to Read Traffic AND Modify/Block it AND Access Cookies
    if (hasAllUrls && hasCookies && (hasWebRequest || hasScripting)) {
        score += 0.3; // Boost score for dangerous combo
    }

    // 3. Content Script Targeting (Man-in-the-Browser)
    // Look for content scripts injecting into banking domains or broad patterns
    if (fullJson.find("content_scripts") != std::string::npos) {
        if (fullJson.find("matches") != std::string::npos) {
            // Crude check for broad matching in content scripts
            if (fullJson.find("*://*/*") != std::string::npos) score += 0.2;
        }
    }

    // 4. Persistence/Update Check
    // "background" permission is common, but combined with the above it's risky
    if (fullJson.find("\"background\"") != std::string::npos) score += 0.1;

    return score;
}

// --------------------------------------------------------------------------------
// Obfuscation Detector
// --------------------------------------------------------------------------------
bool ExtensionScanner::CheckForObfuscation(const fs::path& dir) {
    // Check .js files in the folder
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() == ".js") {
            std::ifstream file(entry.path());
            std::string line;
            // Check first few lines. Malware is often packed into one massive line 
            // or contains "eval(" or hex strings.
            if (std::getline(file, line)) {
                if (line.length() > 5000) return true; // Suspiciously long line (packed)
                if (line.find("eval(") != std::string::npos) return true;
                if (line.find("var _0x") != std::string::npos) return true; // Common obfuscator var
            }
        }
    }
    return false;
}

// --------------------------------------------------------------------------------
// Simple Parsing Helpers (Robustness > Speed)
// --------------------------------------------------------------------------------
std::string ExtensionScanner::ExtractJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";

    size_t start = json.find(":", pos) + 1;
    size_t firstQuote = json.find("\"", start);
    size_t endQuote = json.find("\"", firstQuote + 1);

    if (firstQuote != std::string::npos && endQuote != std::string::npos) {
        return json.substr(firstQuote + 1, endQuote - firstQuote - 1);
    }
    return "";
}

std::vector<std::string> ExtensionScanner::ExtractJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> results;
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return results;

    size_t arrayStart = json.find("[", pos);
    size_t arrayEnd = json.find("]", arrayStart);

    if (arrayStart == std::string::npos || arrayEnd == std::string::npos) return results;

    std::string arrayContent = json.substr(arrayStart + 1, arrayEnd - arrayStart - 1);

    // Split by comma
    std::stringstream ss(arrayContent);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        // Clean up quotes and whitespace
        size_t first = segment.find("\"");
        size_t last = segment.rfind("\"");
        if (first != std::string::npos && last != std::string::npos && last > first) {
            results.push_back(segment.substr(first + 1, last - first - 1));
        }
    }
    return results;
}

std::vector<ChromeExtension> ExtensionScanner::GetFlaggedExtensions() {
    return flaggedExtensions;
}