#include "SystemScanner.h"
#include <iostream>
#include <sstream>

SystemScanner::SystemScanner() {}

// ─────────────────────────────────────────────────────────────
// SHARED HELPER
// ─────────────────────────────────────────────────────────────
bool SystemScanner::scanAndFlag(const std::wstring& wPath, const std::string& context,
    std::vector<std::string>& findings)
{
    std::string narrowPath(wPath.begin(), wPath.end());

    bool certClean = certScanner.checkSignature(wPath);
    std::string hash = SigScanner::getMD5Hash(narrowPath);
    bool vtClean = hash.empty() ? true : SigScanner::scanWithVirusTotal(hash);

    if (!certClean || !vtClean) {
        std::string finding = "[" + context + "] " + narrowPath;
        if (!certClean) finding += " — unsigned/untrusted certificate";
        if (!vtClean)   finding += " — VirusTotal signature match";
        findings.push_back(finding);

        // Pipe to deep analysis asynchronously
        std::thread([narrowPath]() {
            SigScanner::connectToDeepAnalyze("systemScan!" + narrowPath);
            }).detach();

        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────
// THREAD 1: Registry Run keys + Startup folder
// ─────────────────────────────────────────────────────────────
void SystemScanner::scanStartupLocations(std::vector<std::string>& findings, bool& threatFound)
{
    std::cout << "[SystemScanner] Scanning startup locations...\n";

    struct RegTarget { HKEY hive; const wchar_t* key; };
    std::vector<RegTarget> targets = {
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"     },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"     },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    };

    for (auto& target : targets) {
        HKEY hKey;
        if (RegOpenKeyExW(target.hive, target.key, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        wchar_t valueName[512], valueData[1024];
        DWORD nameSize, dataSize, type, index = 0;

        while (true) {
            nameSize = 512; dataSize = sizeof(valueData);
            LONG ret = RegEnumValueW(hKey, index++, valueName, &nameSize,
                nullptr, &type, (LPBYTE)valueData, &dataSize);
            if (ret == ERROR_NO_MORE_ITEMS) break;
            if (ret != ERROR_SUCCESS || type != REG_SZ) continue;

            // Strip quotes and arguments — keep only the executable path
            std::wstring raw(valueData);
            if (!raw.empty() && raw[0] == L'"') {
                size_t end = raw.find(L'"', 1);
                raw = raw.substr(1, end != std::wstring::npos ? end - 1 : std::wstring::npos);
            }
            else {
                size_t space = raw.find(L' ');
                if (space != std::wstring::npos) raw = raw.substr(0, space);
            }

            if (raw.empty() || !fs::exists(raw)) continue;

            if (!scanAndFlag(raw, "STARTUP_REG", findings))
                threatFound = true;
        }
        RegCloseKey(hKey);
    }

    // Startup folder
    wchar_t startupPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath) == S_OK) {
        for (auto& entry : fs::directory_iterator(startupPath)) {
            if (entry.is_regular_file()) {
                if (!scanAndFlag(entry.path().wstring(), "STARTUP_FOLDER", findings))
                    threatFound = true;
            }
        }
    }

    std::cout << "[SystemScanner] Startup locations done.\n";
}

// ─────────────────────────────────────────────────────────────
// THREAD 2: Scheduled Tasks (XML parse)
// ─────────────────────────────────────────────────────────────
void SystemScanner::scanScheduledTasks(std::vector<std::string>& findings, bool& threatFound)
{
    std::cout << "[SystemScanner] Scanning scheduled tasks...\n";

    fs::path tasksDir = L"C:\\Windows\\System32\\Tasks";
    if (!fs::exists(tasksDir)) return;

    auto extractTag = [](const std::string& xml, const std::string& tag) -> std::wstring {
        std::string open = "<" + tag + ">";
        std::string close = "</" + tag + ">";
        size_t s = xml.find(open);
        size_t e = xml.find(close, s);
        if (s == std::string::npos || e == std::string::npos) return L"";
        std::string val = xml.substr(s + open.size(), e - s - open.size());
        val.erase(0, val.find_first_not_of(" \t\r\n"));
        val.erase(val.find_last_not_of(" \t\r\n") + 1);
        return std::wstring(val.begin(), val.end());
        };

    for (auto& entry : fs::recursive_directory_iterator(
        tasksDir, fs::directory_options::skip_permission_denied))
    {
        if (!entry.is_regular_file()) continue;

        std::ifstream file(entry.path());
        if (!file) continue;
        std::string xml((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

        std::wstring command = extractTag(xml, "Command");
        if (command.empty()) continue;

        std::wstring lower = command;
        for (auto& c : lower) c = towlower(c);
        if (lower.find(L"c:\\windows\\") == 0) continue; // skip system tasks

        if (!fs::exists(command)) continue;

        if (!scanAndFlag(command, "SCHEDULED_TASK", findings))
            threatFound = true;
    }

    std::cout << "[SystemScanner] Scheduled tasks done.\n";
}

// ─────────────────────────────────────────────────────────────
// THREAD 3: Installed Services (SCM)
// ─────────────────────────────────────────────────────────────
void SystemScanner::scanInstalledServices(std::vector<std::string>& findings, bool& threatFound)
{
    std::cout << "[SystemScanner] Scanning installed services...\n";

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) {
        findings.push_back("[SERVICES] Failed to open SCM — run as administrator");
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, nullptr, 0,
        &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded,
        &bytesNeeded, &servicesReturned, &resumeHandle, nullptr))
    {
        CloseServiceHandle(hScm);
        return;
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    for (DWORD i = 0; i < servicesReturned; i++) {
        SC_HANDLE hSvc = OpenServiceW(hScm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD configBytes = 0;
        QueryServiceConfigW(hSvc, nullptr, 0, &configBytes);
        std::vector<BYTE> configBuf(configBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuf.data());

        if (!QueryServiceConfigW(hSvc, config, configBytes, &configBytes)) {
            CloseServiceHandle(hSvc); continue;
        }

        std::wstring binaryPath(config->lpBinaryPathName);
        CloseServiceHandle(hSvc);

        // Strip arguments
        if (!binaryPath.empty() && binaryPath[0] == L'"') {
            size_t end = binaryPath.find(L'"', 1);
            binaryPath = binaryPath.substr(1, end != std::wstring::npos ? end - 1 : std::wstring::npos);
        }
        else {
            size_t space = binaryPath.find(L' ');
            if (space != std::wstring::npos) binaryPath = binaryPath.substr(0, space);
        }

        std::wstring lower = binaryPath;
        for (auto& c : lower) c = towlower(c);
        if (lower.find(L"c:\\windows\\") == 0 ||
            lower.find(L"c:\\program files\\") == 0) continue;

        if (!fs::exists(binaryPath)) continue;

        if (!scanAndFlag(binaryPath, "SERVICE", findings))
            threatFound = true;
    }

    CloseServiceHandle(hScm);
    std::cout << "[SystemScanner] Services done.\n";
}

// ─────────────────────────────────────────────────────────────
// JSON WRITER
// ─────────────────────────────────────────────────────────────
void SystemScanner::writeResult(const std::vector<std::string>& findings, bool threatFound)
{
    std::string verdict = threatFound ? "THREATS_DETECTED" : "CLEAN";

    std::string findingsJson = "[";
    for (size_t i = 0; i < findings.size(); ++i) {
        std::string f = findings[i];

        // Replace backslashes with forward slashes — no escaping needed at all
        for (auto& c : f) if (c == '\\') c = '/';

        findingsJson += "\"" + f + "\"";
        if (i + 1 < findings.size()) findingsJson += ",";
    }
    findingsJson += "]";

    const char* tempDir = std::getenv("TEMP");
    std::string resultPath = std::string(tempDir ? tempDir : "C:\\Temp")
        + "\\aegis_scan_result.json";

    std::ofstream resultFile(resultPath);
    resultFile << "{\"verdict\":\"" << verdict << "\",\"findings\":" << findingsJson << "}";
    resultFile.close();

    std::cout << "[SystemScanner] Result written — " << verdict
        << " (" << findings.size() << " findings)\n";
}

// ─────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────
void SystemScanner::runFullScan()
{
    std::cout << "[SystemScanner] Full system scan started...\n";

    std::vector<std::string> findings;
    std::mutex findingsMutex;
    bool threatFound = false;

    auto runStartup = [&]() {
        std::vector<std::string> local; bool threat = false;
        scanStartupLocations(local, threat);
        std::lock_guard<std::mutex> lock(findingsMutex);
        findings.insert(findings.end(), local.begin(), local.end());
        if (threat) threatFound = true;
        };

    auto runTasks = [&]() {
        std::vector<std::string> local; bool threat = false;
        scanScheduledTasks(local, threat);
        std::lock_guard<std::mutex> lock(findingsMutex);
        findings.insert(findings.end(), local.begin(), local.end());
        if (threat) threatFound = true;
        };

    auto runServices = [&]() {
        std::vector<std::string> local; bool threat = false;
        scanInstalledServices(local, threat);
        std::lock_guard<std::mutex> lock(findingsMutex);
        findings.insert(findings.end(), local.begin(), local.end());
        if (threat) threatFound = true;
        };

    std::thread t1(runStartup);
    std::thread t2(runTasks);
    std::thread t3(runServices);
    t1.join(); t2.join(); t3.join();

    if (findings.empty())
        findings.push_back("All startup locations, scheduled tasks, and services are clean");

    writeResult(findings, threatFound);
}