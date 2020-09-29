#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H
#include "ProxyContext.h"

#include "event2/listener.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_ssl.h"

#include <mutex>
#include <string>
#include <vector>

class ProxyServer
{
public:
	ProxyServer();

	virtual ~ProxyServer();

	static std::shared_ptr<ProxyServer> Get();

	virtual inline void SetIP(const std::string& InIP);
	virtual inline std::string GetIP();

	virtual inline void SetPort(int InPort);
	virtual inline int GetPort();

	virtual inline event_base* GetEventHandle();

	virtual bool InitServer();

	static void StaticOnListenerAccepted(evconnlistener* InListener, evutil_socket_t Socket, SOCKADDR* Address, int SockLen, void* Arg);

	virtual void OnListenerAcceptedWrapper(evconnlistener* InListener, evutil_socket_t Socket, SOCKADDR* Address, int SockLen, void* Arg);

	static void StaticOnSocketReadable(bufferevent* Event, void* Context);

	virtual void OnSocketReadableWrapper(bufferevent* Event, void* Context);

	static void StaticOnSocketWritable(bufferevent* Event, void* Context);

	virtual void OnSocketWritableWrapper(bufferevent* Event, void* Context);

	static void StaticOnRecvEvent(struct bufferevent* BufferEvent, short Reason, void* Context);

	virtual void OnRecvEventWrapper(struct bufferevent* BufferEvent, short Reason, void* Context);

	static void StaticEventLog(int Severity, const char* Message);

protected:
	static std::once_flag InstanceOnceFlag;
	static std::shared_ptr<ProxyServer> Instance;

	std::string ServerIP;
	int ServerPort;

	event_base* EventHandle;
	evconnlistener* Listener;

	std::vector<std::shared_ptr<ProxyContext>> ContextList;
};

#endif // !PROXY_SERVER_H
