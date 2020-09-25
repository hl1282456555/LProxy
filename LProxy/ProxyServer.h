#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "ProxyBase.h"

#include <mutex>
#include <vector>

struct ClientSocket
{
	SOCKADDR_IN Addr;
	SOCKET		SockHandle;
};

class ProxyServer : public ProxyBase
{
public:
	ProxyServer();
	virtual ~ProxyServer();

	virtual void Run();

	virtual bool Listen();

	static void SignalHandler(int Signal);

protected:
	std::vector<ClientSocket>	ClientList;
};

#endif // !PROXY_SERVER_H
