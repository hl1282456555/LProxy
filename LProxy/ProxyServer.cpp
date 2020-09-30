#include "ProxyServer.h"
#include "EasyLog.h"

#include <WinSock2.h>
#include <WS2tcpip.h>

std::once_flag ProxyServer::InstanceOnceFlag;
std::shared_ptr<ProxyServer> ProxyServer::Instance;

ProxyServer::ProxyServer()
	: ServerIP("localhost")
	, ServerPort(1080)
	, Listener(INVALID_SOCKET)
	, SSLContext(nullptr)
{
	InitSSLContext();
}

ProxyServer::~ProxyServer()
{
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
		
	}

	return true;
}

void ProxyServer::ProcessWorker()
{

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

void ProxyServer::InitWorkThread()
{
	int workerNum = std::thread::hardware_concurrency() * 2;
	LOG(Log, "%d workers created for this machine.", workerNum);

	for (int index = 0; index < workerNum; index++)
	{
		WorkerThreads.push_back(std::thread(std::bind(&ProxyServer::ProcessWorker, this)));
		WorkerThreads.back().detach();
	}
}

