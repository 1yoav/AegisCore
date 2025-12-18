#include <windows.h>
#include <iostream>
#include <string>

void createPipe(wchar_t* pipeName)
{
    std::wcout << L"[+] Pipe server started at: " << pipeName << std::endl;

    while (true)
    {
        HANDLE hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_INBOUND, // server only reads
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0,                  // no outbound buffer
            4096,               // inbound buffer
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

        std::cout << "[+] Client connected" << std::endl;

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
            {
                DWORD err = GetLastError();

                if (err == ERROR_BROKEN_PIPE)
                {
                    std::cout << "[*] Client disconnected" << std::endl;
                }
                else
                {
                    std::cerr << "[-] ReadFile failed. Error: "
                        << err << std::endl;
                }
                break;
            }

            buffer[bytesRead] = '\0';
            std::cout << "[>] Received: " << buffer << std::endl;
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}