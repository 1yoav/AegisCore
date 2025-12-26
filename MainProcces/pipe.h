#pragma once

#include <windows.h>
#include <iostream>


void createPipe(wchar_t* pipe);
std::wstring getNameByPid(int pid);
