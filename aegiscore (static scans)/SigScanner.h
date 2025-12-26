#pragma once

#pragma warning(disable : 4996)

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <thread>
#include <iostream>
#include <windows.h>
#include <fcntl.h> 
#include <io.h> 
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>
#include <tlhelp32.h>
#include <vector>

class SigScanner
{
public:

	SigScanner() = default;
	void checkSignature(std::filesystem::path);
	static bool scanWithVirusTotal(const std::string& fileHash);
	static std::string getMD5Hash(const std::filesystem::path& path);
	// static void quarantineFile(const std::filesystem::path& filePath);

	std::vector<std::wstring> files;
};