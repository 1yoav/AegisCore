#include "UiCom.h"

UiCom::UiCom()
{
    //activate the communication too the ui
	std::thread(&UiCom::start, this).detach();
}

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
    else
    {
        command = "start /b \"\" python \"" + GetPythonScriptPath(procces);
    }
    std::system(command.c_str());
}

void UiCom::killScan(std::string& procces)
{
    std::string command = "powershell -Command \"Get-CimInstance Win32_Process | "
        "Where-Object { $_.CommandLine -like '*" + procces + "*' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }\"";

    std::system(command.c_str());
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
