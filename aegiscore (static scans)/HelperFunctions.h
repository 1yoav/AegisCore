#pragma once
#include <shlobj.h>
#include <string>

// Add inline here
inline std::wstring GetFolder(REFKNOWNFOLDERID rfid) {
    PWSTR path = NULL;
    HRESULT hr = SHGetKnownFolderPath(rfid, 0, NULL, &path);
    if (SUCCEEDED(hr)) {
        std::wstring res(path);
        CoTaskMemFree(path);
        return res;
    }
    return L"";
}

inline const char* boolToString(bool b) {
    return b ? "TRUE (Trusted)" : "FALSE (Suspicious)";
}