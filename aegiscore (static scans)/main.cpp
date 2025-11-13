#include <iostream>
#include "SQLDatabase.h"

int main(void)
{
	std::cout << "Welcome to AegisCore! Passive Scanner activated.\n\n";

	std::cout << "INitializing databse...\n";

	sqlite3* database = nullptr;
	SQLDatabase db(database, "DATABASE");


	return 0;
}