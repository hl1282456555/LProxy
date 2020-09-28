#include "ProxyServer.h"
#include "EasyLog.h"

#include <WS2tcpip.h>
#include <csignal>

static bool bStopServer = false;
std::once_flag ProxyServer::InstanceOnceFlag;
std::shared_ptr<ProxyServer> ProxyServer::Instance;

ProxyServer::ProxyServer()
	: ProxyBase()
{
	signal(SIGINT, ProxyServer::SignalHandler);
}

ProxyServer::~ProxyServer()
{
		
}

std::shared_ptr<ProxyServer> ProxyServer::Get()
{
	std::call_once(InstanceOnceFlag,
	[&]()
	{
		Instance = std::make_shared<ProxyServer>();
	});

	return Instance;
}

void ProxyServer::Run()
{
	
	if (!Listen()) {
		return;
	}

	LOG(Log, "Start listening...");

	while (!bStopServer && SockHandle != INVALID_SOCKET)
	{
		SOCKADDR_IN acceptAddr;
		int len = sizeof(SOCKADDR);
		SOCKET acceptSock = accept(SockHandle, (SOCKADDR*)&acceptAddr, &len);
		if (acceptSock != SOCKET_ERROR) {

			char acceptHost[16] = { 0 };
			InetNtopA(AF_INET, &acceptAddr.sin_addr, acceptHost, 16);
			LOG(Log, "Accept a new client, addr: %s, port: %d", acceptHost, acceptAddr.sin_port);

			std::shared_ptr<ClientSocket> client(new ClientSocket(acceptAddr, acceptSock));
			if (client->InitConnection()) {
				ClientList.push_back(client);
			}
		}
	}
}

bool ProxyServer::Listen()
{

	if (!IsValid()) {
		SockState = ESocketState::Initialized;
		LOG(Error, "Startup listen server failed, err: The socket not initialized.");
		return false;
	}

	SOCKADDR_IN serverAddr;
	std::memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(SockPort);
	InetPtonA(AF_INET, SockIP.c_str(), &serverAddr.sin_addr.S_un);

	if (bind(SockHandle, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		SockState = ESocketState::Initialized;
		LOG(Error, "Startup listen server failed, err: Bind server ip and port failed.");
		return false;
	}

	if (listen(SockHandle, SOMAXCONN) < 0) {
		SockState = ESocketState::Initialized;
		LOG(Error, "Startup listen server failed, err: Call listen failed.");
		return false;
	}

	SockState = ESocketState::Connecting;
	return true;
}

void ProxyServer::SignalHandler(int Signal)
{
	bStopServer = true;
}

void ProxyServer::CloseClient(const std::shared_ptr<ClientSocket>& Client)
{
	std::lock_guard<std::mutex> clientListScope(ClientListLock);

	if (std::remove_if(ClientList.begin(), ClientList.end(), [&](const std::shared_ptr<ClientSocket>& Other) { return Client == Other; }) == ClientList.end()) {
		LOG(Warning, "The client specified for destruction was not found.");
	}
}
