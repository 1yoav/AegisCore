#include "SQLDatabase.h"
#include <fstream>
#include <iostream>
#include <io.h>
#include <filesystem>
#include <Windows.h>

using std::cout;
using std::endl;
namespace fs = std::filesystem;

bool SQLDatabase::open()
{
    int file_exist = _access(m_dbFileName.c_str(), 0);
    int res = sqlite3_open(this->m_dbFileName.c_str(), &this->m_db);
    if (res != SQLITE_OK)
    {
        m_db = nullptr;
        std::cout << "Failed to open DB" << std::endl;
        return false;
    }

    // create a new db if it dosent exist
    if (file_exist != 0)
    {
        const char* sqlStatement = R"(
            CREATE TABLE PROCESSES (
                PID INTEGER PRIMARY KEY NOT NULL,
                StartTime TEXT NOT NULL,
                EndTime TEXT,
                ProcessName TEXT NOT NULL,
                ExePath TEXT NOT NULL,
                UserName TEXT,
                HashSHA256 TEXT,
                SignedBy TEXT,
                InitialTrigger TEXT,
                CurrentScore REAL DEFAULT 0,
                Verdict TEXT DEFAULT 'under_review' CHECK(Verdict IN ('benign','suspicious','malicious','under_review')),
                LastSeen TEXT NOT NULL
            );
            CREATE TABLE CIDR_IPS (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                StartIP INTEGER NOT NULL,
                EndIP INTEGER NOT NULL
            );
        )";

        
        res = sqlite3_exec(m_db, sqlStatement, nullptr, nullptr, &m_errMessage);
        if (res != SQLITE_OK)
        {
            std::cerr << "Failed to create PROCESSES table: " << m_errMessage << std::endl;
            sqlite3_free(m_errMessage);
            return false;
        }

        // create table if initialization is successful
        addC2Ips();

        std::cout << "Database initialized and PROCESSES table created." << std::endl;
    }

    return true;
}

// void SQLDatabase::importIps
bool SQLDatabase::close()
{
	if (!m_db)
	{
		return false;
	}
	sqlite3_close(this->m_db);
	this->m_db = nullptr;
	return true;
}

int SQLDatabase::addNewProcess(string username, string password, string email)
{

    return 0;
}

void SQLDatabase::addC2Ips()
{
    // Use GetDatabasePath() logic to find the file relative to the exe
    wchar_t exeBuf[MAX_PATH];
    GetModuleFileNameW(NULL, exeBuf, MAX_PATH);
    fs::path exeDir = fs::path(exeBuf).parent_path();
    fs::path installRoot = exeDir.parent_path().parent_path().parent_path();
    fs::path filePath = installRoot / "aegiscore (static scans)" / "dependencies" / "firehol_level1.netset.txt";

    std::ifstream fireholIps(filePath);
    if (!fireholIps.is_open()) {
        std::cerr << "[ERROR] Could not open blocklist file: "
            << filePath.string() << std::endl;
        return; // non-fatal, just skip
    }

    std::cout << "[INFO] Importing CIDR ranges to database..." << std::endl;

    // 1. Start a Transaction (MASSIVE speed increase)
    char* errMsg = nullptr;
    sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, &errMsg);

    // 2. Prepare the INSERT statement once
    const char* sqlInsert = "INSERT INTO CIDR_IPS (StartIP, EndIP) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(m_db, sqlInsert, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare INSERT statement: " << sqlite3_errmsg(m_db) << std::endl;
        return;
    }

    std::string line;
    int count = 0;

    while (getline(fireholIps, line)) {
        // Simple trim to handle potential \r on Windows lines or leading spaces
        line.erase(0, line.find_first_not_of(" \t\r\n"));

        // Skip empty lines or comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        try {
            // Convert string to integer range
            IpRange range = cidrToRange(line);

            // Bind the values to the statement (Index 1 is StartIP, Index 2 is EndIP)
            // We use bind_int64 to safely hold the unsigned 32-bit integer
            sqlite3_bind_int64(stmt, 1, range.start);
            sqlite3_bind_int64(stmt, 2, range.end);

            // Execute the insert
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                std::cerr << "[WARN] Failed to insert line: " << line << std::endl;
            }

            // Reset the statement for the next loop iteration
            sqlite3_reset(stmt);
            count++;

        }
        catch (const std::exception& e) {
            // Catch invalid_argument from cidrToRange so one bad line doesn't crash the app
            std::cerr << "[WARN] Skipping invalid CIDR '" << line << "': " << e.what() << std::endl;
        }
    }

    // 3. Finalize
    sqlite3_finalize(stmt); // Clean up the statement
    sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, &errMsg); // Write everything to disk

    std::cout << "[INFO] Successfully imported " << count << " CIDR ranges into database." << std::endl;
}

std::vector<FilterRule> SQLDatabase::getC2Rules()
{
    std::vector<FilterRule> dbRules;
    const char* sql = "SELECT StartIP, EndIP FROM CIDR_IPS";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(m_db) << std::endl;
        return dbRules;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // SQLite returns int64 (long long), cast to uint32
        uint32_t startIp = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
        uint32_t endIp = static_cast<uint32_t>(sqlite3_column_int64(stmt, 1));

        // Create the rule using Constructor #4
        // We label it "Known Malicious CIDR"
        dbRules.emplace_back(startIp, endIp, FilterType::BLOCK_IP, "Known Malicious CIDR");
    }

    sqlite3_finalize(stmt);
    return dbRules;
}