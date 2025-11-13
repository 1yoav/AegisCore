#include "sqlite3.h"
#include <string>

using std::string;

struct Process // contaions information we need about certain process
{
	int pid;
	std::string startTime; // dd/mm/yy
	std::string endTime;       
	std::string processName;
	std::string exePath;
	std::string userName;
	std::string hashSHA256;
	// std::string signedBy; currently we dont mess around w hashes. can potentially be useful if we have any spare time
	std::string initialTrigger;
	double currentScore = 0.0; // score of how sure the system is of it being a virus. of course 100% would be highly dangerous
	std::string lastSeen; 

};

class SQLDatabase
{
public:

	SQLDatabase(sqlite3* db, std::string dbFileName) : m_db(db), m_dbFileName(dbFileName), m_errMessage(nullptr) { open(); };
	~SQLDatabase() = default;

	// no need for interface or virtual functions; highly doubt we'll inpliment a non sql databse
	virtual bool open(); // opens/creates db
	virtual bool close();

	virtual int addNewProcess(string username, string password, string email);

private:
	
	// fields for database creation
	sqlite3* m_db;
	std::string m_dbFileName;
	char* m_errMessage;

};



#pragma once
