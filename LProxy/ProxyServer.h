#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "ProxyBase.h"
#include "ClientSocket.h"

#include <vector>

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
