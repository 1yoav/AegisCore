#pragma once

inline const char* boolToString(bool b) {
    return b ? "TRUE (Trusted)" : "FALSE (Suspicious)";
}