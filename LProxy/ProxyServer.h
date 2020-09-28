#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "ProxyBase.h"
#include "ProxyContext.h"

#include <mutex>
#include <queue>

class ProxyServer : public ProxyBase
{
public:
	ProxyServer();
	virtual ~ProxyServer();

	static std::shared_ptr<ProxyServer> Get();

	virtual void Run();

	virtual void ProcessRequest() override;

protected:
	static std::once_flag InstanceOnceFlag;
	static std::shared_ptr<ProxyServer> Instance;

	std::queue<std::shared_ptr<ProxyContext>> PendingQueue;
	std::queue<std::shared_ptr<ProxyContext>> DestroyQueue;

	std::mutex PendingLock;
	std::mutex DestroyLock;
};

#endif // !PROXY_SERVER_H
