#include "ProxyServer.h"
#include "EasyLog.h"

#include <WinSock2.h>
#include <WS2tcpip.h>

std::once_flag ProxyServer::InstanceOnceFlag;
std::shared_ptr<ProxyServer> ProxyServer::Instance;
std::mutex ProxyServer::ContextListLock;
bool ProxyServer::bStopService = false;

ProxyServer::ProxyServer()
	: ServerIP("localhost")
	, ServerPort(1080)
	, Listener(INVALID_SOCKET)
	, SSLContext(nullptr)
{
	InitSSLContext();

	InitWorkerThread();
}

ProxyServer::~ProxyServer()
{
	bStopService = true;
	
	if (Listener != INVALID_SOCKET) {
		closesocket(Listener);
	}

	SSL_CTX_free(SSLContext);
	WSACleanup();
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

void ProxyServer::SetIP(const std::string& InIP)
{
	ServerIP = InIP;
}

std::string ProxyServer::GetIP()
{
	return ServerIP;
}

void ProxyServer::SetPort(int InPort)
{
	ServerPort = InPort;
}

int ProxyServer::GetPort()
{
	return ServerPort;
}

SSL_CTX* ProxyServer::GetSSLContext()
{
	return SSLContext;
}

bool ProxyServer::RunServer()
{	
	if (Listener != INVALID_SOCKET) {
		LOG(Error, "Don't init a server twice.");
		return false;
	}

	LOG(Log, "Initing server...");

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		LOG(Error, "Startup WSA failed.");
		return false;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		LOG(Error, "Incorrect socket library version.");
		return false;
	}

	SOCKADDR_IN addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(ServerPort);
	InetPtonA(AF_INET, ServerIP.c_str(), &addr.sin_addr);

	Listener = socket(AF_INET, SOCK_STREAM, 0);
	if (Listener == INVALID_SOCKET) {
		LOG(Error, "Create a new listener socket failed, code: %d", WSAGetLastError());
		return false;
	}

	if (bind(Listener, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		LOG(Error, "Bind listener to %s:%d failed, code: %d", ServerIP.c_str(), ServerPort, WSAGetLastError());
		return false;
	}

	if (listen(Listener, 0) == SOCKET_ERROR) {
		LOG(Error, "Make listener start listen failed, code: %d", WSAGetLastError());
		return false;
	}

	LOG(Log, "Server start listen at [%s:%d]", ServerIP.c_str(), ServerPort);

	while (true)
	{
		SOCKADDR_IN acceptedAddr;
		std::memset(&acceptedAddr, 0, sizeof(acceptedAddr));
		int addrLen = sizeof(acceptedAddr);
	
		SOCKET acceptedSock = accept(Listener, (SOCKADDR*)&acceptedAddr, &addrLen);

		if (acceptedSock == INVALID_SOCKET) {
			LOG(Error, "Incoming a new connection, but can't accept, code: %d", WSAGetLastError());
			continue;
		}
		
		char addrBuffer[16] = { 0 };
		InetNtopA(AF_INET, (SOCKADDR*)&acceptedAddr.sin_addr, addrBuffer, 16);
		LOG(Log, "Accept a new connection from %s:%d.", addrBuffer, acceptedAddr.sin_port);

		std::shared_ptr<ProxyContext> context(std::make_shared<ProxyContext>(acceptedSock));

		std::lock_guard<std::mutex> contextListScope(ContextListLock);
		ContextList.push(context);

	}

	return true;
}

void ProxyServer::InitSSLContext()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSLContext = SSL_CTX_new(SSLv23_client_method());
	if (SSLContext == nullptr) {
		ERR_print_errors_fp(stdout);
		exit(-1);
	}
}

void ProxyServer::InitWorkerThread()
{
	int workerNum = std::thread::hardware_concurrency() * 2;
	LOG(Log, "Will create %d threads for this machine.", workerNum);

	for (int index = 0; index < workerNum; index++)
	{
		WorkerThreads.push_back(std::thread(
		[&]()
		{
			while (!bStopService)
			{
				bool bEmptyQueue = false;
				std::shared_ptr<ProxyContext> context;
				{
					std::lock_guard<std::mutex> contextListScope(ContextListLock);
					bEmptyQueue = ContextList.empty();
					if (!bEmptyQueue) {
						context = ContextList.front();
						ContextList.pop();
					}
				}

				if (bEmptyQueue) {
					std::this_thread::sleep_for(std::chrono::milliseconds(20));
					continue;
				}

				bool bRequestClose = false;

				EConnectionState state = context->GetConnectionState();
				switch (state)
				{
				case EConnectionState::WaitHandShake:
					context->ProcessWaitHandshake();
					break;

				case EConnectionState::WaitLicense:
					context->ProcessWaitLicense();
					break;

				case EConnectionState::Connected:
				case EConnectionState::UDPAssociate:
					context->ProcessForwardData();
					break;

				default:
					bRequestClose = true;
					break;
				}

				if (bRequestClose) {
					continue;
				}

				std::lock_guard<std::mutex> contextListScope(ContextListLock);
				ContextList.push(context);
			}
		}));

		WorkerThreads.back().detach();
	}
}
