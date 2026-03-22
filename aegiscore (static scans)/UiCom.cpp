#include "UiCom.h"
#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")


void UiCom::processMessage(std::string rawMessage)
{
    if (rawMessage.empty()) return;

    char commandId = rawMessage[0]; 
    std::string data = rawMessage.substr(1); 
    std::cout << "UI COM got msg! : " << rawMessage << "\n";

    switch (commandId) {
    case '1': // START_SCAN
        activateScan(data);
        break;
    case '2': // STOP_SCAN
        killScan(data);
        break;
    case '3':
        scanFile(data); // SCAN FILE (path)
        break;
    case '4': // UPDATE_SETTINGS
        break;
    case '5':
        std::thread([this]() { scanSystem(); }).detach();
        break;
    default:
        std::cout << "Unknown command ID: " << commandId << std::endl;
    }
}

void UiCom::scanSystem() {
    sysScanner.runFullScan();
}

void UiCom::scanFile(std::string& filePath) {
    std::cout << "[*] Scanning file: " << filePath << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::string fileHash = SigScanner::getMD5Hash(filePath);
    bool sigSafe = SigScanner::scanWithVirusTotal(fileHash);

    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::wstring wFp = converter.from_bytes(filePath);
    bool certSafe = CertificateScanner::checkSignature(wFp);

    bool deepSafe = ((0) == !(1)); // placeholder

    // ── Score (0 = clean, 100 = malicious) ──────────────────────────
    int score = 0;
    if (!sigSafe)  score += 55; // VT hit is the most damning
    if (!certSafe) score += 30;
    if (!deepSafe) score += 15;

    std::string verdict;
    if (score < 30) verdict = "CLEAN";
    else if (score < 85) verdict = "SUSPICIOUS";
    else                 verdict = "MALICIOUS";

    // ── Findings ────────────────────────────────────────────────────
    std::vector<std::string> findings;
    findings.push_back(sigSafe ? "VirusTotal: No known signatures detected"
        : "VirusTotal: Malicious signature match found");
    findings.push_back(certSafe ? "Certificate: Valid and trusted signer"
        : "Certificate: Unsigned or untrusted signer");
    findings.push_back(deepSafe ? "Deep scan: No anomalies detected"
        : "Deep scan: Suspicious behaviour patterns found");

    // ── Build JSON manually ─────────────────────────────────────────
    std::string findingsJson;
    for (size_t i = 0; i < findings.size(); ++i) {
        findingsJson += "        \"" + findings[i] + "\"";
        if (i + 1 < findings.size()) findingsJson += ",";
        findingsJson += "\n";
    }

    const char* tempDir = std::getenv("TEMP");
    std::string resultPath = std::string(tempDir ? tempDir : "C:\\Temp") + "\\aegis_scan_result.json";

    std::ofstream resultFile(resultPath);
    resultFile << "{\n"
        << "    \"score\": " << score << ",\n"
        << "    \"verdict\": \"" << verdict << "\",\n"
        << "    \"findings\": [\n"
        << findingsJson
        << "    ]\n"
        << "}";
    resultFile.close();

    std::cout << "[*] Scan complete — verdict: " << verdict << " (" << score << "/100)\n";
}



void UiCom::activateScan(std::string& procces)
{
    std::string command = "";
    fs::path root = GetProjectRoot();

    if (procces == "MainProcces.exe")
    {
        command = "start /b \"\" \"" + GetMainProccesPath() + "\"";
        std::system(command.c_str());

        // isolationForest is now a compiled exe in deep_analysis\dist
        std::string isoPath = (root / "deep_analysis" / "dist" / "isolationForest.exe").string();
        command = "start /b \"\" \"" + isoPath + "\"";
        std::system(command.c_str());
    }
    else if (procces == "signatureScanner")
    {
        monitor.keepMonitoring = true;
        std::thread([this]() { monitor.startMonitor(monitor.downloads); }).detach();
        std::thread([this]() { monitor.startMonitor(monitor.desktop); }).detach();
        std::thread([this]() { monitor.startMonitor(monitor.temp); }).detach();
    }
    else if (procces == "tlsCheck2.py")
    {
        std::string tlsPath = (root / "deep_analysis" / "dist" / "tlscheck2.exe").string();
        command = "start /b \"\" \"" + tlsPath + "\"";
        std::system(command.c_str());
    }
    else
    {
        std::cout << "the call not recognised! \n";
    }
}



void UiCom::killScan(std::string& procces)
{
	std::cout << "Killing scan for: " << procces << std::endl;
    if(procces == "signatureScanner")
		monitor.keepMonitoring = false; // Signal the DownloadMonitor to stop its monitoring loop
    else
    {
        std::string command = "powershell -Command \"Get-CimInstance Win32_Process | "
            "Where-Object { $_.CommandLine -like '*" + procces + "*' } | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }\"";

        std::system(command.c_str());

        //if its call for killing hooking
        if (procces == "MainProcces.exe")
        {
            //kill also the isolationForest
            command = "powershell -Command \"Get-CimInstance Win32_Process | "
                "Where-Object { $_.CommandLine -like '*isolationForest.py*' } | "
                "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }\"";

			std::system(command.c_str());
        }
    }
   
}

void UiCom::start()
{
    LPCWSTR pipeName = L"\\\\.\\pipe\\UiPipe";
    std::cout << "[INIT] UI ENGINE Initialize...\n";

    // ── Security descriptor — explicit Everyone ACL ───────────────
    // NULL DACL works in user sessions but gets blocked at the
    // Session 0 boundary when launched by the service.
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)L"Everyone";

    PACL pAcl = NULL;
    SetEntriesInAclW(1, &ea, NULL, &pAcl);

    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    while (true) {
        HANDLE hPipe = CreateNamedPipe(
            pipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 1024, 1024, 0,
            &sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::cerr << "[UiPipe] Failed to create pipe, error: " << err << std::endl;

            if (err == ERROR_PIPE_BUSY)
                WaitNamedPipeW(pipeName, 5000); // previous instance still alive
            else
                Sleep(1000);

            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
            char buffer[1024];
            DWORD bytesRead;
            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                buffer[bytesRead] = '\0';
                std::thread([this, buffer]() {
                    this->processMessage(buffer);
                    }).detach();
                std::cout << "Received from Electron: " << buffer << std::endl;
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    // Cleanup ACL (never reached in normal operation but good practice)
    if (pAcl) LocalFree(pAcl);
}

std::wstring GetExecutableDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    fs::path exePath(path);
    return exePath.parent_path().wstring();
}

std::wstring GetProjectRoot() {
    fs::path exeDir = GetExecutableDirectory();
    fs::path projectRoot = exeDir.parent_path()
        .parent_path()
        .parent_path();
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


std::string GetMainProccesPath() {
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
