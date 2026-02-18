#include <iostream>

int main() 
{

	// TODO: download all the missing depencies for the AegisCore

	//run the deep Analyze
	std::system("deep_analyze.exe");
	//run the signature scan
	std::system("signature_scan.exe");
	//run the hooking
	std::system("hooking.exe");
	//run the tls cert check
	std::system("tlsCert2.exe");


}