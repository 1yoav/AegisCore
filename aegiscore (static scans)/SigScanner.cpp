#include "SigScanner.h"
#include <openssl/md5.h>
#include <iomanip>
#include <sstream>

// convert file to MD5 string
std::string SigScanner::getMD5Hash(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";

    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        MD5_Update(&md5Context, buffer, file.gcount());
    }

    unsigned char result[MD5_DIGEST_LENGTH];
    MD5_Final(result, &md5Context);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) 
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    }
    return ss.str();
}

//connect to deep analysis pipe and send message
void SigScanner::connectToDeepAnalyze(std::string msg)
{
	std::wstring pipeName = L"\\.\\pipe\\AVDeepScanPipe";

    HANDLE hPipe = CreateFileW(
        pipeName.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );


    WriteFile(hPipe, msg.c_str(), (DWORD)msg.size(), NULL, NULL);
	CloseHandle(hPipe);
}

void SigScanner::checkSignature(std::filesystem::path path)
{
    {
        std::lock_guard<std::mutex> lock(vectorMutex);
        files.push_back(path.wstring());
    }
	//just for testing, send all files to deep analysis
    connectToDeepAnalyze("signatureScanner!" + std::string(path.string()));


    files.push_back(path);

    // 1. Generate the hash
    std::string fileHash = getMD5Hash(path);
    if (fileHash.empty()) {
        //std::wcout << L"Error generating hash for: " << path.wstring() << std::endl;
        return;
    }

    //std::wcout << L"Scanning hash: " << std::wstring(fileHash.begin(), fileHash.end()) << std::endl;

    // 2. Pass the HASH to the scan function instead of the path
    bool isSafe = scanWithVirusTotal(fileHash);

    if (!isSafe)
    {
        std::wcout << L"??  THREAT DETECTED: " << path << std::endl;
        std::wcout << L"Quarantining malicious file... (TODO)" << std::endl;

		//send msg to deep analysis
		connectToDeepAnalyze("signatureScanner!" + std::string(path.string()));
        // quarantineFile(path); // no need for this. file will be sent to deeper analysis
    }
    else
    {
        std::wcout << "? File is safe: " << path << std::endl;
    }
}

// Updated to accept a std::string (the hash)
bool SigScanner::scanWithVirusTotal(const std::string& fileHash)
{
    // Create command to run Python script with the HASH as the argument
    std::string pythonCommand = "python virus_scanner.py " + fileHash;

    std::cout << "Executing: " << pythonCommand << std::endl;

    FILE* pipe = _popen(pythonCommand.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Error: Could not execute Python script!" << std::endl;
        return true;
    }

    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof buffer, pipe) != NULL)
    {
        result += buffer;
    }

    int exitCode = _pclose(pipe);

    // Logic remains the same, checking for your Python script's print statements
    if (result.find("File potentially dangerous!") != std::string::npos)
    {
        return false;
    }
    else if (result.find("File signature is safe!") != std::string::npos)
    {
        return true;
    }

    return true;
}