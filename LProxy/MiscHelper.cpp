#include "MiscHelper.h"
#include "EasyLog.h"

#include <sstream>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ctime>
#include <winsock.h>

std::string MiscHelper::GetDateNow()
{
	std::stringstream ss;

	auto date = std::chrono::system_clock::now().time_since_epoch();

	ss << date.count();

	return ss.str();
}

std::string MiscHelper::GetDateTime()
{
	auto date = std::chrono::system_clock::now();
	auto timeDate = std::chrono::system_clock::to_time_t(date);

	struct tm* time = localtime(&timeDate);
	char buffer[60] = { 0 };
	sprintf(buffer, "%d-%02d-%02d-%02d.%02d.%02d",
		(int)time->tm_year + 1900, (int)time->tm_mon + 1, (int)time->tm_mday,
		(int)time->tm_hour, (int)time->tm_min, (int)time->tm_sec);

	return buffer;
}

void MiscHelper::CloseProcessByHandle(DWORD ProcessId)
{
	EnumWindows(
	[](HWND WindowHandle, LPARAM Param) -> BOOL
	{
		DWORD* procForKill = (DWORD*)Param;

		DWORD dwProcId;
		GetWindowThreadProcessId(WindowHandle, &dwProcId);

		if (*procForKill == dwProcId) {
			SendMessage(WindowHandle, WM_QUIT, 0, 0);
			return FALSE;
		}

		return TRUE;
	}, (LPARAM)&ProcessId);
}

Json MiscHelper::LoadConfig()
{
	std::filesystem::path configPath(L"./Configs.json");

	Json config;

	LOG(Log, "Loading config file : %s", std::filesystem::absolute(configPath).string().c_str());

	std::ifstream fileStream(std::filesystem::absolute(configPath), std::ios::in);
	if (!fileStream.is_open()) {
		LOG(Warning, "Can't find config file.");
		return config;
	}

	std::string configData;

	char tempLine[MAX_BUF_SIZE];
	while (!fileStream.eof()) 
	{
		fileStream.getline(tempLine, MAX_BUF_SIZE);
		configData += tempLine;
	}

	config = Json::parse(configData);

	LOG(Log, "Configs: %s", config.dump(4).c_str());

	fileStream.close();

	return config;
}

std::string MiscHelper::GetLocalHost()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		LOG(Error, "Can't init wsa.");
		return "(null)";
	}

	char hostName[256];
	if (gethostname(hostName, sizeof(hostName)) != 0) {
		LOG(Error, "Can't get hotname.");
		return "(null)";
	}

	hostent* host = gethostbyname(hostName);
	if (host == nullptr) {
		LOG(Error, "Can't get host by name.");
		return "(null)";
	}

	char ipBuffer[32];
	std::strcpy(ipBuffer, inet_ntoa(*(in_addr*)*host->h_addr_list));
	return ipBuffer;
}
