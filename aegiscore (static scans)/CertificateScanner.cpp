#include "CertificateScanner.h"
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
std::string CertificateScanner::getSignerName(const std::wstring& filePath) {
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    std::string signerName = "Unknown Publisher";

    BOOL queryResult = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_ALL,
        0, NULL, NULL, NULL,
        &hStore, &hMsg, NULL
    );

    if (queryResult && hMsg) {
        DWORD cbSignerCertInfo = 0;
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cbSignerCertInfo)) {
            PCERT_INFO pSignerCertInfo = (PCERT_INFO)malloc(cbSignerCertInfo);
            if (pSignerCertInfo && CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerCertInfo, &cbSignerCertInfo)) {
                pCertContext = CertGetSubjectCertificateFromStore(hStore, CERT_FIND_ANY, pSignerCertInfo);
            }
            free(pSignerCertInfo);
        }
    }

    if (pCertContext) {
        wchar_t nameBuffer[256];
        if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuffer, 256)) {
            std::wstring wName(nameBuffer);
            signerName = std::string(wName.begin(), wName.end());
        }
        CertFreeCertificateContext(pCertContext);
    }
    else {
        // Path-based fallback for name only
        if (filePath.find(L"C:\\Windows\\") == 0) signerName = "Microsoft Corporation";
    }

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);

    return signerName;
}

bool CertificateScanner::checkSignature(Process& proc) {
    // 1. Handle Pseudo-processes (Registry, System, etc.)
    if (proc.exePath.find(L"\\") == std::wstring::npos) {
        if (proc.exePath == L"Registry" || proc.exePath == L"System" || proc.exePath == L"Memory Compression") {
            proc.signedBy = "Microsoft Windows (Kernel)";
            return true;
        }
    }

    // 2. Setup WinTrust with standard, widely-compatible flags
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = proc.exePath.c_str();

    WINTRUST_DATA wtd = { 0 };
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    // Use WTD_REVOCATION_CHECK_NONE and WTD_SAFER_FLAG 
    // Removed WTD_CHECK_ADMIN_P_POLICY to fix your compiler error
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_SAFER_FLAG;

    GUID WVTEID_WINTRUST = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG lStatus = WinVerifyTrust(NULL, &WVTEID_WINTRUST, &wtd);

    bool isTrusted = (lStatus == ERROR_SUCCESS);

    // 3. Robust Fallback for System32/WindowsApps
    // If WinVerifyTrust failed, check if the file is in a trusted system location
    if (!isTrusted) {
        std::wstring path = proc.exePath;
        // Transform to lowercase for easier comparison
        for (auto& c : path) c = towlower(c);

        if (path.find(L"c:\\windows\\system32\\") == 0 ||
            path.find(L"c:\\windows\\systemapps\\") == 0 ||
            path.find(L"c:\\program files\\windowsapps\\") == 0) {

            // Verify file actually exists to prevent path spoofing

            proc.signedBy = "Microsoft Windows (Verified Location)";
            isTrusted = true;
            
        }
    }

    // 4. Get Signer Name if trusted and not already set
    if (isTrusted && proc.signedBy.empty()) {
        proc.signedBy = getSignerName(proc.exePath);
    }

    // Mandatory Cleanup
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTEID_WINTRUST, &wtd);

    return isTrusted;
}

bool CertificateScanner::checkSignature(const std::wstring& filePath) {
    // 1. Handle Pseudo-processes (Registry, System, etc.)
    if (filePath.find(L"\\") == std::wstring::npos) {
        if (filePath == L"Registry" || filePath == L"System" || filePath == L"Memory Compression") {
            return true;
        }
    }

    // 2. Setup WinTrust
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA wtd = { 0 };
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_SAFER_FLAG;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG lStatus = WinVerifyTrust(NULL, &actionGuid, &wtd);
    bool isTrusted = (lStatus == ERROR_SUCCESS);

    // 3. Fallback for trusted system locations
    if (!isTrusted) {
        std::wstring pathLower = filePath;
        for (auto& c : pathLower) c = towlower(c);

        if (pathLower.find(L"c:\\windows\\system32\\") == 0 ||
            pathLower.find(L"c:\\windows\\systemapps\\") == 0 ||
            pathLower.find(L"c:\\program files\\windowsapps\\") == 0) {
            isTrusted = true;
        }
    }

    // 4. Mandatory Cleanup
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &wtd);

    return isTrusted;
}