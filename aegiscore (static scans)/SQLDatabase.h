#pragma once
#include "sqlite3.h"
#include "Ip.h"
#include "Process.h"
#include "FilterRule.h"


using std::string;


class SQLDatabase
{
public:

	SQLDatabase(sqlite3* db, std::string dbFileName) : m_db(db), m_dbFileName(dbFileName), m_errMessage(nullptr) { //open();
	};
	~SQLDatabase() = default;

	// no need for interface or virtual functions; highly doubt we'll inpliment a non sql databse
	virtual bool open(); // opens/creates db
	virtual bool close();

	virtual int addNewProcess(string username, string password, string email);
	std::vector<FilterRule> getC2Rules();


private:

	void addC2Ips(); // add known c2 adresses to ip table
	
	// fields for database creation
	sqlite3* m_db;
	std::string m_dbFileName;
	char* m_errMessage;

};