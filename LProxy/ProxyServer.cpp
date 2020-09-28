#include "ProxyServer.h"
#include "EasyLog.h"

#include <WS2tcpip.h>

std::once_flag ProxyServer::InstanceOnceFlag;
std::shared_ptr<ProxyServer> ProxyServer::Instance;

ProxyServer::ProxyServer()
	: ProxyBase()
{
	
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
	LOG(Log, "[Server]Start listening...");

	while (SockHandle != INVALID_SOCKET)
	{
		SOCKADDR_IN acceptAddr;
		int len = sizeof(SOCKADDR);
		SOCKET acceptSock = accept(SockHandle, (SOCKADDR*)&acceptAddr, &len);
		if (acceptSock != SOCKET_ERROR) {

			// Make client socket enable non-blocking method
			unsigned long sockMode(1);
			if (ioctlsocket(acceptSock, FIONBIO, &sockMode) != NO_ERROR) {
			LOG(Warning, "[Server]Set non-blocking method failed.");
			}

			char acceptHost[16] = { 0 };
			InetNtopA(AF_INET, &acceptAddr.sin_addr, acceptHost, 16);
			LOG(Log, "[Server]Accept a new client, addr: %s, port: %d", acceptHost, acceptAddr.sin_port);

			std::shared_ptr<ProxyContext> client(new ProxyContext(acceptAddr, acceptSock));

			std::lock_guard<std::mutex> pendingScope(PendingLock);
			PendingQueue.push(client);

			std::lock_guard<std::mutex> destroyScope(DestroyLock);
			if (DestroyQueue.empty()) {
				continue;
			}
			DestroyQueue.front().reset();
			DestroyQueue.pop();
		}
	}
}

void ProxyServer::ProcessRequest()
{
	while (!bStopServer)
	{
		std::lock_guard<std::mutex> pendingScope(PendingLock);
		if (PendingQueue.empty()) {
			continue;
		}
		
		std::shared_ptr<ProxyContext> client = PendingQueue.front();
		PendingQueue.pop();

		std::chrono::system_clock::time_point currentTime = std::chrono::system_clock::now();
		std::chrono::seconds timeOut(15);
		std::chrono::duration passedTime = currentTime - client->GetStartTime();
		if (passedTime >= timeOut) {
			LOG(Log, "[Server]Connection wait timeout, connection uid: %s.", client->GetGuid().c_str());
			std::lock_guard<std::mutex> destroyScope(DestroyLock);
			DestroyQueue.push(client);
			continue;
		}

		bool bShouldDestroy = false;

		EConnectionState clientState = client->GetState();
		switch (clientState)
		{
		case EConnectionState::None:
		{
			if (client->ProcessHandshake()) {
				break;
			}

			LOG(Warning, "[Client: %s]Try to process handshake with client failed, will drop this connection.", client->GetGuid().c_str());
			bShouldDestroy = true;
			break;
		}

		case EConnectionState::Handshark:
		{
			if (client->ProcessLicenseCheck()) {
				LOG(Log, "[Client: %s]Data travel startup.", client->GetGuid().c_str());
				break;
			}

			LOG(Warning, "[Client: %s]Try to process license check failed, will drop this connection.", client->GetGuid().c_str());
			bShouldDestroy = true;
			break;
		}
		
		case EConnectionState::Connected:
		{
			client->ProcessForwardData();
			break;
		}

		case EConnectionState::RequestClose:
		{
			LOG(Log, "[Client %s]Client request close, will drop this connection.", client->GetGuid().c_str());
			bShouldDestroy = true;
			break;
		}
		default:
		{
			LOG(Warning, "[Client: %s]Wrong connection state.", client->GetGuid().c_str());
			bShouldDestroy = true;
			break;
		}
		}

		if (bShouldDestroy) {
			std::lock_guard<std::mutex> destroyScope(DestroyLock);
			DestroyQueue.push(client);
		}
		else {
			PendingQueue.push(client);
		}
	}
}
