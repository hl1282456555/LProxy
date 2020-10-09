#include "MiscHelper.h"
#include "EasyLog.h"

#include <sstream>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ctime>
#include <random>
#include <WS2tcpip.h>

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

bool MiscHelper::GetLocalHostS(unsigned long& IP)
{
	char hostName[256];
	if (gethostname(hostName, sizeof(hostName)) != 0) {
		LOG(Error, "Can't get hotname.");
		return "(null)";
	}

	ADDRINFO info, * result;
	std::memset(&info, 0, sizeof(ADDRINFO));
	info.ai_family = AF_INET;

	int error = getaddrinfo(hostName, nullptr, &info, &result);
	if (error != 0) {
		LOG(Warning, "Convert hostname to ip address failed, err: %s.", gai_strerrorA(error));
		return false;
	}

	IP = ((SOCKADDR_IN*)(result->ai_addr))->sin_addr.s_addr;

	freeaddrinfo(result);
	
	return true;
}

std::string MiscHelper::NewGuid(int Length)
{
	std::stringstream stream;

	for (int length = 0; length < Length; length++)
	{
		std::random_device device;
		std::mt19937 generator(device());
		std::uniform_int_distribution<> distribution(0, 255);

		std::stringstream hexStream;
		hexStream << std::hex << distribution(generator);
		std::string hexStr = hexStream.str();

		stream << (hexStr.length() < 2 ? '0' + hexStr : hexStr);
	}

	return stream.str();
}

bool MiscHelper::GetAvaliablePort(unsigned short Port, bool bTCP, int IPType)
{
	SOCKET sock = socket(IPType, bTCP ? SOCK_STREAM : SOCK_DGRAM, 0);

	SOCKADDR_IN addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = IPType;
	addr.sin_addr.s_addr = htonl(ADDR_ANY);
	addr.sin_port = 0;

	int state = bind(sock, (SOCKADDR*)&addr, sizeof(addr));
	if (state != 0) {
		closesocket(sock);
		return false;
	}

	SOCKADDR_IN resultAddr;
	std::memset(&resultAddr, 0, sizeof(resultAddr));
	int addrLen = static_cast<int>(sizeof(resultAddr));
	state = getsockname(sock, (SOCKADDR*)&resultAddr, &addrLen);
	if (state != 0) {
		closesocket(sock);
		return false;
	}

	Port = ntohs(resultAddr.sin_port);
	closesocket(sock);
	return true;
}
