#include <windows.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include "pipe.h"
#include <TlHelp32.h>
#include <fileSystem>


std::string wstring_to_string(const std::wstring wstr)
{
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(size_needed - 1, 0); // exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size_needed, nullptr, nullptr);
    return str;
}

void createPipe(wchar_t* pipeName)
{
    std::wcout << L"[+] Pipe server started at: " << pipeName << std::endl;

    std::vector<std::string> featureList = {
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "Sleep",
        "CreateProcess",
        "ProcessSnapshot",
        "ThreadManipulation",
        "MemoryManipulation",
        "TokenPrivileges"
    };

    std::unordered_map<std::string, std::string> apiMap = {
        {"CreateProcessA", "CreateProcess"},
        {"CreateProcessW", "CreateProcess"},
        {"CreateProcessInternalA", "CreateProcess"},
        {"CreateProcessInternalW", "CreateProcess"},
        {"Process32First", "ProcessSnapshot"},
        {"Process32Next", "ProcessSnapshot"},
        {"CreateToolhelp32Snapshot", "ProcessSnapshot"},
        {"SuspendThread", "ThreadManipulation"},
        {"ResumeThread", "ThreadManipulation"},
        {"QueueUserAPC", "ThreadManipulation"},
        {"GetThreadContext", "ThreadManipulation"},
        {"SetThreadContext", "ThreadManipulation"},
        {"CreateRemoteThread", "ThreadManipulation"},
        {"RtlCreateUserThread", "ThreadManipulation"},
        {"NtCreateThreadEx", "ThreadManipulation"},
        {"VirtualAllocEx", "MemoryManipulation"},
        {"WriteProcessMemory", "MemoryManipulation"},
        {"VirtualProtect", "MemoryManipulation"},
        {"OpenProcess", "MemoryManipulation"},
        {"AdjustTokenPrivileges", "TokenPrivileges"},
        {"LookupPrivilegeValue", "TokenPrivileges"},
        {"OpenProcessToken", "TokenPrivileges"},
        {"ReadFile", "ReadFile"},
        {"WriteFile", "WriteFile"},
        {"CloseHandle", "CloseHandle"},
        {"Sleep", "Sleep"}
    };

    //create the lines in the csv
    

    while (true)
    {
        HANDLE hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0,
            4096,
            0,
            nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            std::wcerr << L"[-] CreateNamedPipe failed. Error: "
                << GetLastError() << std::endl;
            return;
        }

        BOOL connected = ConnectNamedPipe(hPipe, nullptr) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected)
        {
            CloseHandle(hPipe);
            continue;
        }

        std::cout << "[+] Client connected\n";

        std::unordered_map<std::string, int> counters;
        for (auto f : featureList)
        {
			counters[f] = 0;
        }
        std::string pid;
        std::string streamBuffer;

        while (true)
        {
            char buffer[4096];
            DWORD bytesRead = 0;

            BOOL success = ReadFile(
                hPipe,
                buffer,
                sizeof(buffer) - 1,
                &bytesRead,
                nullptr
            );

            if (!success || bytesRead == 0)
                break;

            buffer[bytesRead] = '\0';
            streamBuffer += buffer;

            size_t pos;
            while ((pos = streamBuffer.find_first_of("\r\n")) != std::string::npos)
            {
                std::string line = streamBuffer.substr(0, pos);
				std::cout << "[DEBUG] Received line: " << line << std::endl;
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();

                streamBuffer.erase(0, pos + 1);

                if (line.empty())
                    continue;

                if (line == "END_WINDOW")
                {
                    if (!pid.empty())
                    {
                        std::ofstream csv;
						std::string name = wstring_to_string(getNameByPid(std::stoi(pid))) + ".csv";
                        if (std::filesystem::exists(name))
                        {
                            csv.open(name, std::ios::app);
                        }
                        else
                        {
							//add the header
                            csv.open(name);
                            for (auto& f : featureList)
                            {
                                if (&(*featureList.begin()) == &f)
                                    csv << f;
                                else
                                {
                                    csv << "," << f;
                                }
                                
                            }
                            csv << "\n";
                            csv.flush();
                                
						}
                        
						//add the data line
                        for (auto& f : counters)
                        {
                            if (&(*counters.begin()) == &f)
                                csv << f.second;
                            else
                            {
                                csv << "," << f.second;
                            }
                           
                        }
                        csv << "\n";
                        csv.flush();
                    }
                    counters.clear();
                    pid.clear();
                }
                else if (pid.empty())
                {
                    pid = line; 
                }
                else
                {
                    counters[apiMap[line]]++;
                }
            }
        }

        std::cout << "[*] Client disconnected\n";
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
