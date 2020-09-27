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

				char acceptHost[16] = { 0 };
				InetNtopA(AF_INET, &acceptAddr.sin_addr, acceptHost, 16);
				LOG(Log, "Accept a new client, addr: %s", acceptHost);

				if (ClientList.size() >= std::thread::hardware_concurrency()) {
					LOG(Warning, "Can't accept more client, no more cpu core for it, will close this client socket.");
					closesocket(acceptSock);
					continue;
				}

				std::shared_ptr<ClientSocket> client(new ClientSocket(acceptAddr, acceptSock));
				if (client->InitConnection()) {
					ClientList.push_back(client);
				}
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

		SOCKADDR_IN serverAddr;
		std::memset(&serverAddr, 0, sizeof(serverAddr));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = SockPort;
		InetPtonA(AF_INET, SockIP.c_str(), &serverAddr.sin_addr.S_un);

		if (bind(SockHandle, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
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

void ProxyServer::CloseClient(const ClientSocket& Client)
{
	std::lock_guard<std::mutex> clientListScope(ClientListLock);

	if (std::remove_if(ClientList.begin(), ClientList.end(), [&](const std::shared_ptr<ClientSocket>& Other) { return Client == *Other; }) == ClientList.end()) {
		LOG(Warning, "The client specified for destruction was not found.");
	}
}
