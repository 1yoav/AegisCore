#include "UiCom.h"


void UiCom::processMessage(std::string rawMessage)
{
    if (rawMessage.empty()) return;

    char commandId = rawMessage[0]; 
    std::string data = rawMessage.substr(1); 

    switch (commandId) {
    case '1': // START_SCAN
        activateScan(data);
    case '2': // STOP_SCAN
        killScan(data);
    case '3': // UPDATE_SETTINGS
        break;
    default:
        std::cout << "Unknown command ID: " << commandId << std::endl;
    }
}

void UiCom::activateScan(std::string& procces)
{
	std::string command;
    if (procces == "MainProcces")
    {
          command = "start /b \"\" \"" + GetMainProccesPath() + "\"";
    }
    else if (procces == "signatureScanner")
    {
        monitor.keepMonitoring = true; 
		monitor.startMonitor(monitor.downloads);
        monitor.startMonitor(monitor.desktop);
		monitor.startMonitor(monitor.temp);
    }
    else
    {
        command = "start /b \"\" python \"" + GetPythonScriptPath(procces);
    }
    std::system(command.c_str());
}



void UiCom::killScan(std::string& procces)
{
    if(procces == "signatureScanner")
		monitor.keepMonitoring = false; // Signal the DownloadMonitor to stop its monitoring loop
    else
    {
        std::string command = "powershell -Command \"Get-CimInstance Win32_Process | "
            "Where-Object { $_.CommandLine -like '*" + procces + "*' } | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }\"";

        std::system(command.c_str());
    }
   
}

void UiCom::start()
{
    LPCWSTR pipeName = L"\\\\.\\pipe\\AegisPipe";

    std::cout << "Waiting for Electron connection..." << std::endl;

	// This loop will keep the pipe server running indefinitely, allowing multiple connections from Electron over time.
    while (true) {
        
        HANDLE hPipe = CreateNamedPipe(
            pipeName,
            PIPE_ACCESS_INBOUND,       
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,                         
            1024,                      
            1024,                      
            0,                         
            NULL                      
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create pipe." << std::endl;
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
            std::cout << "Electron connected!" << std::endl;

            char buffer[1024];
            DWORD bytesRead;

            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL))
            {
                buffer[bytesRead] = '\0'; 
                std::thread([this, buffer]() { this->processMessage(buffer); }).detach();          
                std::cout << "Received from Electron: " << buffer << std::endl;

            }
        }

        //close teh handle
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

    }
}





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
