#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "ProxyBase.h"
#include "ClientSocket.h"

#include <vector>
#include <mutex>

class ProxyServer : public ProxyBase
{
public:
	ProxyServer();
	virtual ~ProxyServer();

	virtual void Run();

	virtual bool Listen();

	static void SignalHandler(int Signal);

	virtual void CloseClient(const ClientSocket& Client);

protected:
	std::vector<std::shared_ptr<ClientSocket>>	ClientList;

	std::mutex ClientListLock;
};

#endif // !PROXY_SERVER_H
