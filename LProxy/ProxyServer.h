#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "ProxyBase.h"

class ProxyServer : public ProxyBase
{
public:
	ProxyServer();
	virtual ~ProxyServer();

	virtual bool Listen();
};

#endif // !PROXY_SERVER_H
