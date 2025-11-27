#include "pipe.h"

void createPipe(wchar_t* pipe)
{
	std::wcout << L"Creating pipe at: " << pipe << std::endl;
	HANDLE hPipe = CreateNamedPipeW(
		pipe,
		PIPE_ACCESS_INBOUND,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		0, 0,
		0,
		nullptr
	);
	if (hPipe == INVALID_HANDLE_VALUE) {
		std::wcout << L"Failed to create pipe. Error: "
			<< GetLastError() << std::endl;
		return;
	}


	while (true)
	{
		BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE :
			(GetLastError() == ERROR_PIPE_CONNECTED);
		if (!connected) {
			std::wcout << L"ConnectNamedPipe failed. Error: "
				<< GetLastError() << std::endl;
			DisconnectNamedPipe(hPipe);
			continue;
		}

		std::cout << "Client connected!" << std::endl;
		char buffer[1000];
		DWORD bytesRead = 0;
		BOOL success = ReadFile(
			hPipe,
			buffer,
			sizeof(buffer) - 1,
			&bytesRead,
			NULL
		);
		if (!success || bytesRead == 0) {
			std::wcout << L"ReadFile failed. Error: "
				<< GetLastError() << std::endl;
			DisconnectNamedPipe(hPipe);
			continue;
		}
		buffer[bytesRead] = '\0';
		std::wcout << L"Received: " << buffer << std::endl;
		DisconnectNamedPipe(hPipe);
	}
	CloseHandle(hPipe);
}
