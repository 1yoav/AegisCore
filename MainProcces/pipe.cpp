#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include "pipe.h"
#include <TlHelp32.h>
#include <filesystem>
#include <chrono> 


std::string wstring_to_string(const std::wstring wstr)
{
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size_needed, nullptr, nullptr);
    return str;
}

void createPipe(wchar_t* pipeName)
{
    std::cout << "[Init] Initializing hooking...\n";

    //create the base dir
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string csv_path = std::string(exePath);
    size_t lastSlash = csv_path.find_last_of("\\/");
    csv_path = csv_path.substr(0, lastSlash);
    csv_path += "\\..\\..\\programs_data_csv\\";


    auto startTime = std::chrono::steady_clock::now();
    const int TRAINING_DURATION_MINUTES = 3;

    std::vector<std::string> featureList = {
        "ReadFile", "WriteFile", "CloseHandle", "Sleep", "CreateProcess",
        "ProcessSnapshot", "ThreadManipulation", "MemoryManipulation", "TokenPrivileges"
    };

    std::map<std::string, std::string> apiMap = {
        {"CreateProcessA", "CreateProcess"}, {"CreateProcessW", "CreateProcess"},
        {"CreateProcessInternalA", "CreateProcess"}, {"CreateProcessInternalW", "CreateProcess"},
        {"Process32First", "ProcessSnapshot"}, {"Process32Next", "ProcessSnapshot"},
        {"CreateToolhelp32Snapshot", "ProcessSnapshot"}, {"SuspendThread", "ThreadManipulation"},
        {"ResumeThread", "ThreadManipulation"}, {"QueueUserAPC", "ThreadManipulation"},
        {"GetThreadContext", "ThreadManipulation"}, {"SetThreadContext", "ThreadManipulation"},
        {"CreateRemoteThread", "ThreadManipulation"}, {"RtlCreateUserThread", "ThreadManipulation"},
        {"NtCreateThreadEx", "ThreadManipulation"}, {"VirtualAllocEx", "MemoryManipulation"},
        {"WriteProcessMemory", "MemoryManipulation"}, {"VirtualProtect", "MemoryManipulation"},
        {"OpenProcess", "MemoryManipulation"}, {"AdjustTokenPrivileges", "TokenPrivileges"},
        {"LookupPrivilegeValue", "TokenPrivileges"}, {"OpenProcessToken", "TokenPrivileges"},
        {"ReadFile", "ReadFile"}, {"WriteFile", "WriteFile"},
        {"CloseHandle", "CloseHandle"}, {"Sleep", "Sleep"}
    };
    HANDLE pythonPipe;
    while (TRUE)
    {
        pythonPipe = CreateFileW(
            L"\\\\.\\pipe\\isolationForest",
            GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL
        );
        if (pythonPipe != INVALID_HANDLE_VALUE) {
            break;
        }
    }
    
	int originalState = 1; // 1 for training, 0 for inference
    while (true)
    {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsedMinutes = std::chrono::duration_cast<std::chrono::minutes>(currentTime - startTime).count();

        int currentTrainingState = (elapsedMinutes < TRAINING_DURATION_MINUTES) ? 1 : 0;
        
		//if the state has changed, notify the isolationForest for update his database
        if(currentTrainingState != originalState) 
        {
            originalState = currentTrainingState;
			std::string pythonMsg = "1,";
            WriteFile(pythonPipe, pythonMsg.c_str(), (DWORD)pythonMsg.size(), NULL, NULL);
		}

        HANDLE hPipe = CreateNamedPipeW(
            pipeName, PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 0, 4096, 0, nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE) return;

        BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(hPipe);
            continue;
        }

        std::map<std::string, int> counters;
        for (auto f : featureList) counters[f] = 0;

        std::string pid;
        std::string streamBuffer;

        while (true)
        {
            char buffer[4096];
            DWORD bytesRead = 0;
            BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            if (!success || bytesRead == 0) break;
            buffer[bytesRead] = '\0';
            streamBuffer += buffer;
            if (bytesRead < (sizeof(buffer) - 1)) break;
        }

        size_t pos;
        while ((pos = streamBuffer.find_first_of("\r\n")) != std::string::npos)
        {
            std::string line = streamBuffer.substr(0, pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            streamBuffer.erase(0, pos + 1);

            if (line.empty()) continue;

            if (line == "END_WINDOW")
            {
                if (!pid.empty())
                {
                    std::wstring wName = getNameByPid(std::stoi(pid));
                    std::string baseName = wstring_to_string(wName);
                    std::string msgForPython;
                    std::string msgForCsv;

                    std::string pythonMsg = baseName + ".pkl,";
                    for (auto& f : counters) {
                        pythonMsg += std::to_string(f.second) + ",";
                    }
                    pythonMsg.pop_back();
                    WriteFile(pythonPipe, pythonMsg.c_str(), (DWORD)pythonMsg.size(), NULL, NULL);

                    if (currentTrainingState == 1)
                    {
                        std::string csvName = csv_path + baseName + ".csv";
                        std::ofstream csv;
                        if (std::filesystem::exists(csvName)) {
                            csv.open(csvName, std::ios::app);
                        }
                        else {
                            csv.open(csvName);
                            std::string header;
                            for (auto& f : counters) header += f.first + ",";
                            header.pop_back();
                            csv << header << "\n";
                        }

                        std::string dataLine;
                        for (auto& f : counters) dataLine += std::to_string(f.second) + ",";
                        dataLine.pop_back();
                        csv << dataLine << "\n";
                        csv.close();
                    }
                    pid.clear();
                }
                break;
            }
            else if (pid.empty()) {
                pid = line;
            }
            else {
                if (apiMap.count(line)) counters[apiMap[line]]++;
            }
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

std::wstring getNameByPid(int pid)
{
    std::wstring processName;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    processName = pe.szExeFile; // process name
                    break;
                }

            } while (Process32Next(hSnapshot, &pe));

        }
        CloseHandle(hSnapshot);
    }
    return processName;
}
