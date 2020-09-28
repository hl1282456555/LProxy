#include "ProxyBase.h"
#include "EasyLog.h"

#include <WS2tcpip.h>
#include <csignal>

bool ProxyBase::bStopServer = false;

void ProxyBase::SignalHandler(int Signal)
{
	bStopServer = true;
}

ProxyBase::ProxyBase()
	: SockIP("localhost")
	, SockPort(1080)
	, bAnyAddr(true)
	, SockHandle(INVALID_SOCKET)
	, SockState(ESocketState::NotInit)
{
	signal(SIGINT, ProxyBase::SignalHandler);

	int concurrency = std::thread::hardware_concurrency() * 2;
	LOG(Log, "[Server]Will create %d thread run on this machine.", concurrency);

	for (int index = 0; index < concurrency; index++)
	{
		WorkerThreads.push_back(std::thread(std::bind(&ProxyBase::ProcessRequest, this)));

		WorkerThreads.back().detach();
	}
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

		LOG(Log, "[Server]Initing socket...");

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
			throw "[Server]Create a new socket failed.";
		}

		SockState = ESocketState::Initialized;
		LOG(Log, "[Server]Socket initialized...");

		SOCKADDR_IN serverAddr;
		std::memset(&serverAddr, 0, sizeof(serverAddr));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(SockPort);
		InetPtonA(AF_INET, SockIP.c_str(), &serverAddr.sin_addr.S_un);

		if (bind(SockHandle, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
			SockState = ESocketState::Initialized;
			throw std::exception("Startup listen server failed, err: Bind server ip and port failed.");
		}

		if (listen(SockHandle, SOMAXCONN) < 0) {
			SockState = ESocketState::Initialized;
			throw std::exception("Startup listen server failed, err: Call listen failed.");
		}

		SockState = ESocketState::Connecting;
		return true;
	}
	catch (const std::exception& Err) {
		LOG(Error, "[Server]Init socket failed, err: %s", Err.what());
		return false;
	}
}