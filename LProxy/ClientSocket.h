#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include <WinSock2.h>

class ClientSocket
{
public:
	ClientSocket();
	ClientSocket(SOCKADDR_IN InAddr, SOCKET	InHandle);
	virtual ~ClientSocket();

	virtual void InitConnection();

protected:
	SOCKADDR_IN Addr;
	SOCKET		SockHandle;
};

#endif // !CLIENT_SOCKET_H
