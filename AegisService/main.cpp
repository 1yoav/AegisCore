#include <filesystem>
#include <Windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <string>
#include <vector>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace fs = std::filesystem;

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD ctrl);
void RunEngine();
bool LaunchInUserSession(const std::wstring& exePath);

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)L"AegisSVC", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    hStatus = RegisterServiceCtrlHandlerA("AegisService", ServiceCtrlHandler);

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(hStatus, &ServiceStatus);

    RunEngine();

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
    }
}

void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
    }
}

// ??? Launch an exe in the active user's desktop session ???????????????????????
// Services run in Session 0 (no desktop). This grabs the logged-in user's
// token and spawns the process in their interactive session instead.
bool LaunchInUserSession(const std::wstring& exePath) {
    // Get the session ID of the user currently at the console
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) return false;

    // Get that user's token
    HANDLE hToken = NULL;
    if (!WTSQueryUserToken(sessionId, &hToken)) return false;

    // Duplicate it as a primary token we can use with CreateProcessAsUser
    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
        SecurityIdentification, TokenPrimary, &hDupToken)) {
        CloseHandle(hToken);
        return false;
    }

    // Build the user's environment block (PATH, APPDATA, etc.)
    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hDupToken, FALSE);

    // CreateProcessAsUser needs a mutable command-line buffer
    std::wstring cmdLine = L"\"" + exePath + L"\"";
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default"; // user's interactive desktop

    BOOL ok = CreateProcessAsUserW(
        hDupToken,
        NULL,
        cmdBuf.data(),
        NULL, NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        pEnv,
        NULL,
        &si, &pi
    );

    if (pEnv)       DestroyEnvironmentBlock(pEnv);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ok;
}

// ??? Launch engine + tray icon ????????????????????????????????????????????????
void RunEngine() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    // Navigate up from AegisService\x64\Release\ to AegisCore root
    fs::path serviceDir = fs::path(path).parent_path(); // Release
    fs::path installRoot = serviceDir
        .parent_path()   // x64
        .parent_path()   // AegisService
        .parent_path();  // AegisCore root

    std::wstring enginePath = (installRoot /
        L"aegiscore (static scans)" / L"x64" / L"Debug" /
        L"aegiscore.exe").wstring();

    std::wstring iconPath = (installRoot /
        L"AegisService" / L"AegisIcon" / L"bin" / L"Debug" /
        L"AegisIcon.exe").wstring();

    // Launch the AV engine — no UI needed, plain CreateProcess is fine
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    CreateProcessW(
        enginePath.c_str(),
        NULL, NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Launch tray icon in the user's interactive desktop session
    // (plain CreateProcess would spawn it invisibly in Session 0)
    LaunchInUserSession(iconPath);
}