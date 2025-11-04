#include "database.h"
#include <iostream>
#include <io.h>

using std::cout;
using std::endl;

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
        )";

        res = sqlite3_exec(m_db, sqlStatement, nullptr, nullptr, &m_errMessage);
        if (res != SQLITE_OK)
        {
            std::cerr << "Failed to create PROCESSES table: " << m_errMessage << std::endl;
            sqlite3_free(m_errMessage);
            return false;
        }

        std::cout << "Database initialized and PROCESSES table created." << std::endl;
    }

    return true;
}

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
