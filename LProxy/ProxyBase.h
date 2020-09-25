#ifndef PROXY_BASE_H
#define PROXY_BASE_H

#include <string>
#include <WinSock2.h>

enum class ESocketState
{
	NotInit = 0,
	Initialized,
	Connecting,
	Closed,
};

class ProxyBase
{
public:
	ProxyBase();
	virtual ~ProxyBase();

	virtual inline std::string GetIP() { return SockIP; }
	virtual inline void SetIP(const std::string& NewIP) { SockIP = NewIP; }

	virtual inline int GetPort() { return SockPort; }
	virtual inline void SetPort(int Port) { SockPort = Port; }

	virtual inline bool GetAnyAddr() { return bAnyAddr; }
	virtual inline void SetAnyAddr(bool bAny) { bAnyAddr = bAny; }

	virtual inline bool IsValid() { return SockHandle != NULL; }

	virtual inline ESocketState GetState() { return SockState; }

	virtual bool InitSocket();

	virtual void Run() = 0;

protected:
	std::string	SockIP;
	int SockPort;
	bool bAnyAddr;
	SOCKET SockHandle;
	ESocketState SockState;
};


#endif // !PROXY_BASE_H
