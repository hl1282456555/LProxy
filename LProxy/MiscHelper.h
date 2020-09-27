#ifndef MISC_HELPER_H
#define MISC_HELPER_H

#include "json.hpp"

#include <string>
#include <windows.h>

using Json = nlohmann::json;

class MiscHelper
{
public:
	static std::string GetDateNow();
	static std::string GetDateTime();
	static void CloseProcessByHandle(DWORD ProcessId);
	static Json	LoadConfig();
	static std::string GetLocalHost();
	static std::string NewGuid(int Length);
};

#endif