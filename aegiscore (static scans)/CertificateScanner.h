#pragma once
#include "Process.h"
#include <string>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")

class CertificateChecker
{
public:
    // This function attempts to verify the signature of the executable 
    // located at Process::exePath.
    // Returns: true if verified and signed by a trusted root, false otherwise.
    bool checkSignature(Process& proc);

private:
    // Helper function to extract the signer name after a successful check
    std::wstring getSignerName(HANDLE fileHandle);
};