#ifndef EASY_LOG_H
#define EASY_LOG_H

#include "MiscHelper.h"

#include <memory>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include <iostream>

#define MAX_BUF_SIZE 4096

enum class ELogLevel {
	Display = 0,
	Log,
	Warning,
	Error,
	Fatal,
};

namespace EasyLog
{
	static bool EASY_DumpToFile = true;
	static bool EASY_ShowColor = true;
	static std::string EASY_Log_Dir = "./Logs";
	static std::string EASY_Log_Ext = ".log";

	enum EConsoleTextColor
	{
		Red			= FOREGROUND_INTENSITY | FOREGROUND_RED,
		Green		= FOREGROUND_INTENSITY | FOREGROUND_GREEN,
		Blue		= FOREGROUND_INTENSITY | FOREGROUND_BLUE,
		Yellow		= FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN,
		Purple		= FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE,
		Cyan		= FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE,
		Gray		= FOREGROUND_INTENSITY,
		White		= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
		HighWhite	= FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
		Black		= 0,
	};
}

class IEasyLog
{
public:
	
	static std::shared_ptr<IEasyLog> Get();

	IEasyLog();

	virtual ~IEasyLog();

	template<typename ...ArgType>
	void PrintLog(ELogLevel LogLevel, const char* Format, ArgType... Args)
	{
		std::lock_guard<std::mutex> printScope(PrintLock);

		std::string time = MiscHelper::GetDateTime();

		std::string logFormat = "[ " + time + " ]" + "[ " + GetLevelName(LogLevel) + " ] : " + Format;

		char buffer[MAX_BUF_SIZE];
		std::snprintf(buffer, MAX_BUF_SIZE, logFormat.c_str(), Args...);
		
		std::string log(buffer);

		EasyLog::EConsoleTextColor textColor = GetLevelColor(LogLevel);

		SetConsoleTextColor(textColor | 0);

		std::cout << log << std::endl;

		SetConsoleTextColor(EasyLog::EConsoleTextColor::White | 0);

		LogFile << log << std::endl;
	}

protected:
	
	std::string GetLevelName(ELogLevel LogLevel);

	EasyLog::EConsoleTextColor GetLevelColor(ELogLevel LogLevel);

	void SetConsoleTextColor(int ColorCode);

private:
	static std::once_flag InstanceFlag;
	static std::shared_ptr<IEasyLog> Instance;

	std::ofstream LogFile;

	std::mutex PrintLock;
};

#define LOG(Level, Format, ...) IEasyLog::Get()->PrintLog(ELogLevel::##Level, ##Format, ##__VA_ARGS__)

#endif // !EASY_LOG_H
