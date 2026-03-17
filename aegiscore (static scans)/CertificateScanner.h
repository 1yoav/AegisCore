#pragma once
#include "AVProcess.h"
#include "Windows.h"


class CertificateScanner
{
public:
    // This function attempts to verify the signature of the executable 
    // located at Process::exePath.
    // Returns: true if verified and signed by a trusted root, false otherwise.
    bool checkSignature(Process& proc);
    static bool checkSignature(const std::wstring& filePath);

private:
    // Helper function to extract the signer name after a successful check
    std::string getSignerName(const std::wstring& filePath);
};