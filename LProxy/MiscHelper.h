#ifndef MISC_HELPER_H
#define MISC_HELPER_H

#include "json.hpp"

#include <string>
#include <WinSock2.h>
#include <windows.h>
#include <vector>

using Json = nlohmann::json;

class MiscHelper
{
public:
	static std::string GetDateNow();
	static std::string GetDateTime();
	static void CloseProcessByHandle(DWORD ProcessId);
	static Json	LoadConfig();
	static bool GetLocalHostS(unsigned long& IP);
	static std::string NewGuid(int Length);
	static bool GetAvaliablePort(unsigned short Port, bool bTCP = true, int IPType = AF_INET);
};

#endif