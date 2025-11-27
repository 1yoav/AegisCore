#include "database.h"

bool createDatabase(const char* path)
{
    sqlite3* db;
    char* err = nullptr;

    if (sqlite3_open(path, &db) != SQLITE_OK)
    {
        std::cerr << "Cannot open DB: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    const char* sql =
        "CREATE TABLE IF NOT EXISTS api_calls ("
        "timestamp TEXT,"
        "function_name TEXT,"
        "process_id INTEGER"
        ");";

    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK)
    {
        std::cerr << "SQL error: " << err << std::endl;
        sqlite3_free(err);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);
    return true;
}


bool insertRecord(const std::string& timestamp,
    const std::string& functionName, int processId)
{
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open(dbPath, &db) != SQLITE_OK)
    {
        std::cerr << "Cannot open DB: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    const char* sql =
        "INSERT INTO api_calls (timestamp, function_name, process_id) "
        "VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement" << std::endl;
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, functionName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, processId);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        std::cerr << "Failed to insert data" << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}