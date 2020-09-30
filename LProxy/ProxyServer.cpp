#include "ProxyServer.h"
#include "EasyLog.h"

#include <WinSock2.h>
#include <WS2tcpip.h>

std::once_flag ProxyServer::InstanceOnceFlag;
std::shared_ptr<ProxyServer> ProxyServer::Instance;

ProxyServer::ProxyServer()
	: ServerIP("localhost")
	, ServerPort(1080)
	, EventHandle(nullptr)
	, Listener(nullptr)
	, SSLContext(nullptr)
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

ProxyServer::~ProxyServer()
{
	if (Listener != nullptr) {
		evconnlistener_free(Listener);
		Listener = nullptr;
	}

	if (EventHandle != nullptr) {
		event_base_free(EventHandle);
		EventHandle = nullptr;
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

event_base* ProxyServer::GetEventHandle()
{
	return EventHandle;
}

SSL_CTX* ProxyServer::GetSSLContext()
{
	return SSLContext;
}

bool ProxyServer::InitServer()
{	
	if (EventHandle != nullptr || Listener != nullptr) {
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

	EventHandle = event_base_new();
	Listener = evconnlistener_new_bind(EventHandle, ProxyServer::StaticOnListenerAccepted, nullptr, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (SOCKADDR*)&addr, sizeof(addr));
	if (Listener == nullptr) {
		LOG(Error, "Create a new listener failed.");
		return false;
	}

	LOG(Log, "Listener startup at %s:%d", ServerIP.c_str(), ServerPort);
	event_base_dispatch(EventHandle);

	return true;
}

void ProxyServer::StaticOnListenerAccepted(evconnlistener* InListener, evutil_socket_t Socket, SOCKADDR* Address, int SockLen, void* Arg)
{
	std::shared_ptr<ProxyServer> server = ProxyServer::Get();
	server->OnListenerAcceptedWrapper(InListener, Socket, Address, SockLen, Arg);
}

void ProxyServer::OnListenerAcceptedWrapper(evconnlistener* InListener, evutil_socket_t Socket, SOCKADDR* Address, int SockLen, void* Arg)
{
	if (InListener != Listener) {
		LOG(Error, "Wrong listener incoming, will drop this connection.");
		return;
	}

	LOG(Log, "Accept a new connextion: %d", Socket);

	std::shared_ptr<ProxyContext> context = std::make_shared<ProxyContext>();
	ContextList.push_back(context);

	event_base* base = evconnlistener_get_base(Listener);
	bufferevent* bufferEvent = bufferevent_socket_new(base, Socket, BEV_OPT_CLOSE_ON_FREE);
	context->SetClientEvent(bufferEvent);
	
	bufferevent_setcb(bufferEvent, ProxyServer::StaticOnSocketReadable, ProxyServer::StaticOnSocketWritable, ProxyServer::StaticOnRecvEvent, ContextList.back().get());
	bufferevent_enable(bufferEvent, EV_READ | EV_WRITE);
}

void ProxyServer::StaticOnSocketReadable(bufferevent* Event, void* Context)
{
	std::shared_ptr<ProxyServer> server = ProxyServer::Get();
	server->OnSocketReadableWrapper(Event, Context);
}

void ProxyServer::OnSocketReadableWrapper(bufferevent* Event, void* Context)
{
	ProxyContext* context = static_cast<ProxyContext*>(Context);
	if (context == nullptr) {
		LOG(Error, "The passed context is invalid, will drop this connection.");
		bufferevent_free(Event);
		return;
	}

	context->OnSocketReadable(Event);
}

void ProxyServer::StaticOnSocketWritable(bufferevent* Event, void* Context)
{
	std::shared_ptr<ProxyServer> server = ProxyServer::Get();
	server->OnSocketWritableWrapper(Event, Context);
}

void ProxyServer::OnSocketWritableWrapper(bufferevent* Event, void* Context)
{
	ProxyContext* context = static_cast<ProxyContext*>(Context);
	if (context == nullptr) {
		LOG(Error, "The passed context is invalid, will drop this connection.");
		bufferevent_free(Event);
		return;
	}

	context->OnSocketSent(Event);
}

void ProxyServer::StaticOnRecvEvent(struct bufferevent* BufferEvent, short Reason, void* Context)
{
	std::shared_ptr<ProxyServer> server = ProxyServer::Get();
	server->OnRecvEventWrapper(BufferEvent, Reason, Context);
}

void ProxyServer::OnRecvEventWrapper(struct bufferevent* BufferEvent, short Reason, void* Context)
{
	ProxyContext* context = static_cast<ProxyContext*>(Context);
	if (context == nullptr) {
		LOG(Error, "The passed context is invalid, will drop this connection.");
		bufferevent_free(BufferEvent);
		return;
	}

	if (Reason & BEV_EVENT_EOF) {
		LOG(Warning, "Connection %d is closed, will free the handle.", bufferevent_getfd(BufferEvent));
		if (context->BeforeDestroyContext(BufferEvent)) {
			auto removeIt = std::remove_if(ContextList.begin(), ContextList.end(), [&](const std::shared_ptr<ProxyContext>& Context) { return !Context->IsValid(); });
			ContextList.erase(removeIt, ContextList.end());
		}
	}
	else if (Reason & BEV_EVENT_CONNECTED) {
		LOG(Log, "Connection %d connect succeeded.", bufferevent_getfd(BufferEvent));
	}
	else if (Reason & BEV_EVENT_ERROR) {
		LOG(Error, "Some errors occurred on the connection %d.", bufferevent_getfd(BufferEvent));
		LOG(Error, "Error: %d", EVUTIL_SOCKET_ERROR());
		LOG(Error, "Will drop this connection and free the conntection handle.");
		if (context->BeforeDestroyContext(BufferEvent)) {
			auto removeIt = std::remove_if(ContextList.begin(), ContextList.end(), [&](const std::shared_ptr<ProxyContext>& Context) { return !Context->IsValid(); });
			ContextList.erase(removeIt, ContextList.end());
		}
	}
}
