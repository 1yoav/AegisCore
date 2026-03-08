#pragma once
//#include "WFPEngine.h"
#include "PacketLogger.h"
#include "FilterRule.h"
#include "SQLDatabase.h"
#include "HelperFunctions.h"
#include "CertificateScanner.h"
#include <future>
//#include "TrafficDiverter.h"
#include "NetworkUtils.h"
#include "AVProcess.h"
#include "PipeClient.h"
#include "SigScanner.h"
#include <iostream>
#include <string>
#include <csignal>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include "DownloadMonitor.h"
#include "ExtensionScanner.h"

namespace fs = std::filesystem;
static std::string GetMainProccesPath();
std::wstring GetExecutableDirectory();
std::string GetDatabasePath();
std::string GetPythonScriptPath(const std::string& scriptName);
static std::string GetMainProccesPath();






class UiCom
{
public:
	UiCom();
	~UiCom() = default;
	void start();
	void processMessage(std::string rawMessage);
	void active(std::string&);
	void kill(std::string&);

};





std::wstring GetExecutableDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    fs::path exePath(path);
    return exePath.parent_path().wstring();
}

std::wstring GetProjectRoot() {
    // From: C:\...\AegisCore\aegiscore (static scans)\x64\Release\MainProcces.exe
    // Go up 3 levels to get to AegisCore root
    fs::path exeDir = GetExecutableDirectory();
    fs::path projectRoot = exeDir.parent_path()  // Remove "Release" or "Debug"
        .parent_path()  // Remove "x64"
        .parent_path(); // Remove "aegiscore (static scans)" or "MainProcces"
    return projectRoot.wstring();
}

std::string GetDatabasePath() {
    fs::path root = GetProjectRoot();
    fs::path dbPath = root / "aegiscore (static scans)" / "dependencies" / "DATABASE";
    return dbPath.string();
}

std::string GetPythonScriptPath(const std::string& scriptName) {
    fs::path root = GetProjectRoot();
    fs::path scriptPath = root / "deep_analysis" / scriptName;
    return scriptPath.string();
}


static std::string GetMainProccesPath() {
    fs::path root = GetProjectRoot();

    // Try Debug first, then Release
    std::vector<fs::path> possiblePaths = {
        root / "MainProcces" / "x64" / "Debug" / "MainProcces.exe",
        root / "MainProcces" / "x64" / "Release" / "MainProcces.exe"
    };

    for (const auto& path : possiblePaths) {
        if (fs::exists(path)) {
            return path.string();
        }
    }

    // Fallback - return Debug path (will error later if not found)
    return possiblePaths[0].string();
}


