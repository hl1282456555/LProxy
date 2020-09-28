#include "ProxyBase.h"
#include "EasyLog.h"

ProxyBase::ProxyBase()
	: SockIP("localhost")
	, SockPort(1080)
	, bAnyAddr(true)
	, SockHandle(INVALID_SOCKET)
	, SockState(ESocketState::NotInit)
{

}

ProxyBase::~ProxyBase()
{
	if (SockHandle == INVALID_SOCKET) {
		return;
	}

	closesocket(SockHandle);
	WSACleanup();
	SockHandle = INVALID_SOCKET;
}

bool ProxyBase::InitSocket()
{
	try {
		if (SockState > ESocketState::NotInit) {
			throw "Socket is already initialized, don't init twice.";
		}

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
		if (SockHandle == INVALID_SOCKET) {
			throw "Create a new socket failed.";
		}

		//unsigned long sockMode(1);
		//if (ioctlsocket(SockHandle, FIONBIO, &sockMode) != NO_ERROR) {
		//	LOG(Warning, "Set non-blocking method failed.");
		//}

		SockState = ESocketState::Initialized;
		LOG(Log, "Socket initialized...");

		return true;
	}
	catch (const std::exception& Err) {
		LOG(Error, "Init socket failed, err: %s", Err.what());
		return false;
	}
}