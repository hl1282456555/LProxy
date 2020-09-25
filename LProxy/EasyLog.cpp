#include "EasyLog.h"

std::once_flag IEasyLog::InstanceFlag;
std::shared_ptr<IEasyLog> IEasyLog::Instance = nullptr;

std::shared_ptr<IEasyLog> IEasyLog::Get()
{
	std::call_once (InstanceFlag, 
	[]()
	{
		Instance = std::make_shared<IEasyLog>();
	});

	return Instance;
}

IEasyLog::IEasyLog()
{
	std::string time = MiscHelper::GetDateTime();

	std::filesystem::path logPath(EasyLog::EASY_Log_Dir);
	if (!std::filesystem::exists(logPath)) {
		std::filesystem::create_directories(logPath);
	}
	
	logPath += "/" + time + EasyLog::EASY_Log_Ext;
	LogFile.open(std::filesystem::absolute(logPath), std::ios::out);
}

IEasyLog::~IEasyLog()
{
	LogFile.close();
}

std::string IEasyLog::GetLevelName(ELogLevel LogLevel)
{
	switch (LogLevel)
	{
	case ELogLevel::Display:
		return "Display";
	case ELogLevel::Log:
		return "Log";
	case ELogLevel::Warning:
		return "Warning";
	case ELogLevel::Error:
		return "Error";
	case ELogLevel::Fatal:
		return "Fatal";
	default:
		return "(null)";
	}
}

EasyLog::EConsoleTextColor IEasyLog::GetLevelColor(ELogLevel LogLevel)
{
	switch (LogLevel)
	{
	case ELogLevel::Display:
	case ELogLevel::Log:
		return EasyLog::White;
	case ELogLevel::Warning:
		return EasyLog::Yellow;
	case ELogLevel::Error:
		return EasyLog::Red;
	case ELogLevel::Fatal:
		return EasyLog::Cyan;
	default:
		return EasyLog::White;
	}
}

void IEasyLog::SetConsoleTextColor(int ColorCode)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(handle, ColorCode);
}
