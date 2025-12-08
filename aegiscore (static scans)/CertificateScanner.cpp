#include "CertificateScanner.h"
#include "AVProcess.h"
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <fstream>
#include <iostream>

#pragma comment(lib, "wintrust.lib")


// Helper macro for error handling
#define CLOSE_AND_RETURN(ret) { \
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile); \
    return ret; \
}

bool CertificateScanner::checkSignature(Process& proc) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    bool isReliable = false;

    // 1. Open the file to verify
    hFile = CreateFileW(
        proc.exePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        // Log this error: File may have been deleted, or permissions blocked
        // For AV purposes, we treat 'cannot check' as 'suspicious' (false).
        CLOSE_AND_RETURN(false);
    }

    // 2. Prepare the WinVerifyTrust structures
    GUID WVTEID_DRIVER = WINTRUST_ACTION_GENERIC_VERIFY_V2; // Generic trust check

    // Structure 1: WINTRUST_FILE_INFO (tells the API which file to check)
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = proc.exePath.c_str();
    fileInfo.hFile = hFile;

    // Structure 2: WINTRUST_DATA (tells the API how to check the file)
    WINTRUST_DATA wtd = { 0 };
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.pPolicyCallbackData = NULL;
    wtd.pSIPClientData = NULL;
    wtd.dwUIChoice = WTD_UI_NONE;             // No user interaction
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE; // Optional: WTD_REVOKE_ALL for full check
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY; // Do the verification
    wtd.hWVTStateData = NULL;
    wtd.pwszURLReference = NULL;
    wtd.dwProvFlags = 0; // might cause unexpected behavior; beware
    wtd.dwUIContext = WTD_UICONTEXT_EXECUTE;

    // 3. Perform the actual verification
    LONG lStatus = WinVerifyTrust(
        NULL,
        &WVTEID_DRIVER,
        &wtd
    );

    // 4. Handle Results and Cleanup
    if (lStatus == ERROR_SUCCESS) {
        // Certificate is valid and chained to a trusted root
        isReliable = true;
        // Set the SignedBy field in the Process structure for logging
        proc.signedBy = std::string(proc.processName.begin(), proc.processName.end()); // You'd call getSignerName here

        // Mandatory cleanup step for WinVerifyTrust success
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &WVTEID_DRIVER, &wtd);
    }
    // else: lStatus indicates failure (e.g., CERT_E_UNTRUSTEDROOT, TRUST_E_NOSIGNATURE)

    CLOSE_AND_RETURN(isReliable);
}