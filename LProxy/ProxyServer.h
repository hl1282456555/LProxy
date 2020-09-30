#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H
#include "ProxyContext.h"

#include "openssl/ssl.h"
#include "openssl/err.h"

#include <mutex>
#include <string>
#include <vector>
#include <queue>
#include <thread>

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

	virtual inline SSL_CTX* GetSSLContext();

	virtual bool RunServer();

	virtual void ProcessWorker();

protected:
	virtual void InitSSLContext();

	virtual void InitWorkThread();

protected:
	static std::once_flag InstanceOnceFlag;
	static std::shared_ptr<ProxyServer> Instance;

	std::string ServerIP;
	int ServerPort;

	SOCKET Listener;

	SSL_CTX* SSLContext;

	std::vector<std::thread>	WorkerThreads;
	std::queue<std::shared_ptr<ProxyContext>> ContextList;
};

#endif // !PROXY_SERVER_H
