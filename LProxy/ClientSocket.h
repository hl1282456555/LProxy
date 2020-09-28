#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include "ProxyStructures.h"

#include <WinSock2.h>
#include <string>
#include <vector>

class ClientSocket
{
public:
	ClientSocket(SOCKADDR_IN InAddr, SOCKET	InHandle);
	virtual ~ClientSocket();

	virtual bool InitConnection();

	virtual void Close();

	bool operator==(const ClientSocket& Other) const;

protected:

	virtual bool ProcessHandshake();

	virtual bool ProcessLicenseCheck();

	virtual bool ProcessConnectCmd(const TravelPayload& Payload);

	virtual bool SendHandshakeResponse(EConnectionProtocol Response);

	virtual bool SendLicenseResponse(const TravelPayload& Payload, ETravelResponse Response);

protected:
	SOCKADDR_IN Addr;
	SOCKET		SockHandle;
	std::string Guid;

	SOCKADDR_IN TransportAddr;
	SOCKET		TransportSockHandle;

	bool bRequestClose;

	EConnectionState State;
};

#endif // !CLIENT_SOCKET_H
