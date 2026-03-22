#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include "pipe.h"
#include <TlHelp32.h>
#include <fileSystem>

#define TRAINING 0


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
    std::cout << "[Init] Initializing hooking...\n";

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

    std::map<std::string, std::string> apiMap = {
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


    //connect to the isolationFirest server
    HANDLE pythonPipe;
    pythonPipe = CreateFileW(
        L"\\\\.\\pipe\\isolationForest",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL


    );
    /*do
    {
        pythonPipe = CreateFileW(
            L"\\\\.\\pipe\\isolationForest",
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL


        );
        if (pythonPipe == INVALID_HANDLE_VALUE)
            Sleep(500);
        else
            break;
    } while (true);*/
    

    while (true)
    {
        //create the communication between the hooking dlls
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

        //check for errors
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            //std::wcerr << L"[-] CreateNamedPipe failed. Error: "
                //<< GetLastError() << std::endl;
            return;
        }

        //connect to client
        BOOL connected = ConnectNamedPipe(hPipe, nullptr) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            CloseHandle(hPipe);
            continue;
        }
        //std::cout << "[+] Client connected\n";

        //create counters for each feature
        std::map<std::string, int> counters;
        for (auto f : featureList)
        {
            counters[f] = 0;
        }
        std::string pid;
        std::string streamBuffer;


        //read all the data from the client
        while (true)
        {
            //define varaibles
            char buffer[4096];
            DWORD bytesRead = 0;
            std::string name;

            //read the data from the client
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
            if (bytesRead < (sizeof(buffer) - 1))
                break;
        }

        size_t pos;
        std::string name;

        while ((pos = streamBuffer.find_first_of("\r\n")) != std::string::npos)
        {
            std::string line = streamBuffer.substr(0, pos);
            //std::cout << "[DEBUG] Received line: " << line << std::endl;
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            streamBuffer.erase(0, pos + 1);

            if (line.empty())
                continue;

            if (line == "END_WINDOW")
            {
                name = wstring_to_string(getNameByPid(std::stoi(pid)));
                if (!pid.empty())
                {
                    std::string msg;
                    if (TRAINING == 1)
                    {
						name += ".csv";
                        std::ofstream csv;
                        if (std::filesystem::exists(name))
                        {
                            csv.open(name, std::ios::app);
                        }
                        else
                        {
                            //add the header
                            csv.open(name);
                            for (auto& f : counters)
                            {
                                msg += f.first + ",";
                            }
                            msg.pop_back();
                            msg += "\n";
                            csv << msg;
                            csv.flush();

                        }

                        msg.clear();

                        //add the data line
                        for (auto& f : counters)
                        {
                            msg += std::to_string(f.second) + ",";
                        }
                        msg.pop_back();
                        msg += "\n";
                        csv << msg;
                        csv.flush();
                        csv.close();
						pid.clear();

                    }
                    //if its not training mode, send to python server
                    else
                    {
                        name += ".pkl";
                        msg = name + ",";
                        //add the counters
                        for (auto& f : counters)
                        {
                            msg += std::to_string(f.second) + ",";
                        }
                        msg.pop_back();

						//send the data to isolationForest server
                        WriteFile(pythonPipe, msg.c_str(), (DWORD)msg.size(), NULL, NULL);
                    }
                }
                break;

            }

            //get the pid of teh sender process
            else if (pid.empty())
            {
                pid = line;
            }
            //count the api calls
            else
            {
                counters[apiMap[line]]++;
            }
        }

        //std::cout << "[*] Client disconnected\n";
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


