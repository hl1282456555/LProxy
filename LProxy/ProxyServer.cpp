#include "ProxyServer.h"
#include "EasyLog.h"

#include <WS2tcpip.h>
#include <csignal>

static bool bStopServer = false;

ProxyServer::ProxyServer()
	: ProxyBase()
{
	signal(SIGINT, ProxyServer::SignalHandler);
}

ProxyServer::~ProxyServer()
{
		
}

void ProxyServer::Run()
{
	LOG(Log, "Start listening...");
	if (!Listen()) {
		return;
	}

	std::thread serverMainThread(
	[&]()
	{
		while (!bStopServer && SockHandle != INVALID_SOCKET)
		{
			SOCKADDR_IN acceptAddr;
			int len = sizeof(acceptAddr);
			SOCKET acceptSock = accept(SockHandle, (SOCKADDR*)&acceptAddr, &len);
			if (acceptSock != SOCKET_ERROR) {

				ClientSocket client(acceptAddr, acceptSock);
				ClientList.push_back(client);
				
				char acceptHost[16];
				InetNtopA(AF_INET, &acceptAddr.sin_addr, acceptHost, 16);
				LOG(Log, "Accept a new client, addr: %s", acceptHost);
			}
		}
	});

	serverMainThread.join();
}

bool ProxyServer::Listen()
{
	try {
		if (!IsValid()) {
			throw "The socket not initialized.";
		}

		SOCKADDR_IN ServerAddr;
		std::memset(&ServerAddr, 0, sizeof(ServerAddr));
		ServerAddr.sin_family = AF_INET;
		ServerAddr.sin_port = SockPort;
		InetPtonA(AF_INET, SockIP.c_str(), &ServerAddr.sin_addr.S_un);

		if (bind(SockHandle, (SOCKADDR*)&ServerAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
			throw "Bind server ip and port failed.";
		}

		if (listen(SockHandle, SOMAXCONN) < 0) {
			throw "Call listen failed.";
		}

		SockState = ESocketState::Connecting;
		return true;
	}
	catch (const std::exception& Err) {
		SockState = ESocketState::Initialized;
		LOG(Error, "Startup listen server failed, err: %s", Err.what());
		return false;
	}
}

void ProxyServer::SignalHandler(int Signal)
{
	bStopServer = true;
}
