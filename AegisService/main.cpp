#include <filesystem>
#include <Windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;
HANDLE hStopEvent;

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void stopEvent();
void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD ctrl);
void RunEngine();
bool LaunchInUserSession(const std::wstring& exePath);
bool LaunchElevatedInUserSession(const std::wstring& exePath);
bool LaunchAsSystemInUserSession(const std::wstring& exePath);

int main(int argc, char* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)L"AegisService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            printf("Debug Mode: Running ServiceMain manually...\n");

            
            ServiceMain(0, NULL);
        }
        else {
            return GetLastError();
        }
    }
    return 0;
}

void stopEvent()
{
    SetEvent(hStopEvent);
    CloseHandle(hStopEvent);
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) 
{
    hStopEvent = CreateEventW(NULL, TRUE, FALSE, L"Global\\AegisStopEvent"); 
    hStatus = RegisterServiceCtrlHandlerA("AegisSVC", ServiceCtrlHandler);

    if (hStatus) {
        ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

        ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

        ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCheckPoint = 0;
        ServiceStatus.dwWaitHint = 0;

        SetServiceStatus(hStatus, &ServiceStatus);
    }

    RunEngine();

    

    WaitForSingleObject(hStopEvent, INFINITE);

    if (hStatus) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
    }

    CloseHandle(hStopEvent);
}


void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) 
    {
        if (hStatus) {
            ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING; // אנחנו בתהליך
            SetServiceStatus(hStatus, &ServiceStatus);
        }
        stopEvent(); 
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

    DWORD dwCreationFlags = CREATE_UNICODE_ENVIRONMENT; 

    BOOL ok = CreateProcessAsUserW(
        hDupToken,
        NULL,
        cmdBuf.data(),
        NULL,
        NULL,
        FALSE,
        dwCreationFlags, 
        pEnv,
        NULL,
        &si,
        &pi
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

// ??? Launch engine + tray icon
void RunEngine() 
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    fs::path serviceDir = fs::path(path).parent_path();
    fs::path installRoot = serviceDir.parent_path()
        .parent_path()
        .parent_path();

    std::wstring enginePath = (installRoot /
        L"aegiscore (static scans)" / L"x64" / L"Debug" /
        L"aegiscore (static scans).exe").wstring();

    std::wstring iconPath = (installRoot /
        L"AegisService" / L"AegisIcon" / L"bin" / L"Debug" /
        L"AegisIcon.exe").wstring();

    // ?? Diagnostic log — remove once working ?????????????????????
    {
        std::wofstream log(L"C:\\Windows\\Temp\\aegis_service_log.txt");
        log << L"Install root:  " << installRoot.wstring() << L"\n";
        log << L"Engine path:   " << enginePath << L"\n";
        log << L"Engine exists: " << fs::exists(enginePath) << L"\n";
        log << L"Icon path:     " << iconPath << L"\n";
        log << L"Icon exists:   " << fs::exists(iconPath) << L"\n";
    }


    /*STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessW(enginePath.c_str(), NULL, NULL, NULL,
        FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    DWORD err = GetLastError();
    {
        std::wofstream log(L"C:\\Windows\\Temp\\aegis_service_log.txt",
            std::ios::app);
        log << L"CreateProcess ok: " << ok
            << L"  error: " << GetLastError() << L"\n";
    }

    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }*/

    LaunchInUserSession(iconPath);
    LaunchAsSystemInUserSession(enginePath); // elevated, user session
}
bool LaunchAsSystemInUserSession(const std::wstring& exePath) {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) return false; // אין משתמש מחובר כרגע

    HANDLE hUserToken = NULL;
    HANDLE hTokenDup = NULL;
    LPVOID pEnv = NULL;
    bool success = false;

    // 1. קבלת ה-Token של המשתמש המחובר ב-Session הפעיל
    if (!WTSQueryUserToken(sessionId, &hUserToken)) {
        return false;
    }

    // 2. שכפול ה-Token כדי שנוכל להשתמש בו ליצירת תהליך חדש (Primary Token)
    if (DuplicateTokenEx(hUserToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hTokenDup)) {

        // 3. הגדרת ה-Session ID בתוך ה-Token המשוכפל
        SetTokenInformation(hTokenDup, TokenSessionId, &sessionId, sizeof(sessionId));

        // 4. יצירת סביבת עבודה (Environment) שמתאימה למשתמש
        if (CreateEnvironmentBlock(&pEnv, hTokenDup, FALSE)) {

            std::wstring cmdLine = L"\"" + exePath + L"\"";
            std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
            cmdBuf.push_back(0);

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = { 0 };

            // הגדרת ה-Desktop כדי שה-GUI יוכל להופיע על מסך המשתמש
            si.lpDesktop = (LPWSTR)L"winsta0\\default";

            // 5. יצירת התהליך ב-Session של המשתמש
            // שימוש ב-CREATE_UNICODE_ENVIRONMENT הכרחי כשמשתמשים ב-pEnv
            if (CreateProcessAsUserW(
                hTokenDup,           // ה-Token של המשתמש ב-Session 1
                NULL,                // נתיב ה-Application
                cmdBuf.data(),       // שורת הפקודה
                NULL, NULL, FALSE,
                CREATE_UNICODE_ENVIRONMENT, // דגלים
                pEnv,                // סביבת המשתמש
                NULL,                // תיקיית עבודה (NULL = זהה לשירות)
                &si, &pi))
            {
                success = true;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

            DestroyEnvironmentBlock(pEnv);
        }
        CloseHandle(hTokenDup);
    }

    CloseHandle(hUserToken);
    return success;
}
bool LaunchElevatedInUserSession(const std::wstring& exePath) {
    // ShellExecuteEx with "runas" triggers UAC elevation in the user session
    // We need to do this via the user's token + ShellExecuteEx

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) return false;

    HANDLE hToken = NULL;
    if (!WTSQueryUserToken(sessionId, &hToken)) return false;

    HANDLE hDupToken = NULL;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
        SecurityImpersonation, TokenPrimary, &hDupToken);
    CloseHandle(hToken);

    // Impersonate the user so ShellExecuteEx runs in their context
    ImpersonateLoggedOnUser(hDupToken);

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";           // triggers UAC elevation
    sei.lpFile = exePath.c_str();
    sei.nShow = SW_HIDE;

    BOOL ok = ShellExecuteExW(&sei);

    RevertToSelf();                  // stop impersonating
    CloseHandle(hDupToken);

    if (ok && sei.hProcess) CloseHandle(sei.hProcess);
    return ok;
}