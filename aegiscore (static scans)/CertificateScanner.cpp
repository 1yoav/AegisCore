// ==================== CertificateScanner.cpp ====================
#include "CertificateScanner.h"
#include "AVProcess.h"
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <iostream>
#include <vector>

// Linker Directives (Ensure these are also in your project settings)
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib") 

// Helper macro for safe cleanup and return
#define CLOSE_AND_RETURN(ret) { \
    /* No file handle to close since WinVerifyTrust handles file access */ \
    return ret; \
}

// ----------------------------------------------------------------
// Helper: Extracts the Subject Name (Publisher/Company) from the signature
// ----------------------------------------------------------------
std::string CertificateScanner::getSignerName(const std::wstring& filePath) {
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    std::string signerName = "Unknown Publisher";

    // 1. Query the file for certificate information
    // Looks for the embedded signature data
    BOOL queryResult = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_OBJECT_FILE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        0,
        NULL,
        NULL,
        NULL,
        &hStore, // Certificate Store
        &hMsg,
        NULL
    );

    if (!queryResult) {
        // This should only happen if the file is unsigned or the signature is corrupted.
        return signerName;
    }

    // 2. Get the certificate context from the store
    // We assume the first certificate found is the primary signer
    pCertContext = CertGetSubjectCertificateFromStore(
        hStore,
        CERT_FIND_ANY,
        0
    );

    if (pCertContext) {
        // 3. Extract the Subject Name (e.g., "Google LLC")
        DWORD size = CertGetNameStringW(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0
        );

        if (size > 1) {
            std::vector<wchar_t> nameBuffer(size);
            CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                NULL,
                nameBuffer.data(),
                size
            );

            // Convert wstring (wchar_t*) to std::string for the database/logging
            std::wstring wName(nameBuffer.data());
            signerName = std::string(wName.begin(), wName.end());
        }
    }

    // 4. Cleanup
    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);

    return signerName;
}


// ----------------------------------------------------------------
// Main Function: Verifies the integrity and trust of the signature
// ----------------------------------------------------------------
bool CertificateScanner::checkSignature(Process& proc) {
    bool isReliable = false;

    // 1. Prepare the File Info structure
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = proc.exePath.c_str();
    fileInfo.hFile = NULL;

    // 2. Prepare the WinTrust Data structure
    WINTRUST_DATA wtd = { 0 };
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.dwUIChoice = WTD_UI_NONE;             // No user interaction
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE; // Optional: Disables online checks for speed
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    // Use flags for robustness: Catalog lookups, only cache retrieval
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    wtd.dwUIContext = WTD_UICONTEXT_EXECUTE;

    // 3. Define the Policy GUID (Standard Authenticode)
    GUID WVTEID_WINTRUST = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // 4. Perform the actual verification
    LONG lStatus = WinVerifyTrust(
        NULL,
        &WVTEID_WINTRUST,
        &wtd
    );

    // 5. Handle Results and Cleanup
    if (lStatus == ERROR_SUCCESS) {
        isReliable = true;

        // Extract the name for logging
        proc.signedBy = getSignerName(proc.exePath);

        // Mandatory cleanup
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &WVTEID_WINTRUST, &wtd);
    }
    // else: lStatus indicates failure

    CLOSE_AND_RETURN(isReliable);
}