#pragma once

#include <iostream>
#include "sqlite3.h"

const char* dbPath = "apiTable";

bool createDatabase(const char* path);
bool insertRecord(const std::string& timestamp,
    const std::string& functionName, int processId);