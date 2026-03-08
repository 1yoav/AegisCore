#pragma once
#include "DownloadMonitor.h"

namespace fs = std::filesystem;

//---------functions for absulute paths----------------//
std::string GetMainProccesPath();
std::wstring GetExecutableDirectory();
std::string GetDatabasePath();
std::string GetPythonScriptPath(const std::string& scriptName);
std::wstring GetProjectRoot();






class UiCom
{
public:
    void start();
    UiCom(SQLDatabase* db) :
        scanner(), certScanner(), extScanner(db), monitor(db) {};
    // Add a user-defined constructor that takes SQLDatabase* for monitor and default-constructs others.

    void processMessage(std::string rawMessage);
    void activateScan(std::string&);
    void killScan(std::string&);

    SigScanner scanner;
    CertificateScanner certScanner;
    ExtensionScanner extScanner;
    DownloadMonitor monitor;
	

};






