#include "ProxyBase.h"
#include "EasyLog.h"

ProxyBase::ProxyBase()
	: SockIP("localhost")
	, SockPort(1080)
	, bAnyAddr(true)
	, SockHandle(NULL)
	, SockState(ESocketState::NotInit)
{

}

ProxyBase::~ProxyBase()
{
	if (SockHandle == NULL) {
		return;
	}

	closesocket(SockHandle);
	WSACleanup();
	SockHandle = NULL;
}

bool ProxyBase::InitSocket(const std::string& IP, int Port)
{
	try {
		if (SockState > ESocketState::NotInit) {
			throw "Socket is already initialized, don't init twice.";
		}

		if (IP.empty()) {
			throw "No necessary information to create socket.";
		}

		SockIP = IP;
		SockPort = Port;

		LOG(Log, "Initing socket...");

		WSADATA wsaData;

		DWORD status = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (status != 0) {
			throw "Init WSA service failed.";
		}

		if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
			WSACleanup();
			throw "WSA version incorrect.";
		}

		SockHandle = socket(AF_INET, SOCK_STREAM, 0);
		if (SockHandle == NULL) {
			throw "Create a new socket failed.";
		}

		SockState = ESocketState::Initialized;
		LOG(Log, "Socket initialized...");
	}
	catch (const std::exception& Err) {
		LOG(Error, "Init socket failed, err: %s", Err.what());
		return false;
	}
}