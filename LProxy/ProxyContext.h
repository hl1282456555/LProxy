#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include "ProxyStructures.h"

#include <WinSock2.h>
#include <string>
#include <vector>
#include <chrono>

class ProxyContext
{
public:
	ProxyContext(SOCKADDR_IN InAddr, SOCKET	InHandle);
	virtual ~ProxyContext();

	virtual void Close();

	bool operator==(const ProxyContext& Other) const;

	virtual inline std::string GetGuid();

	virtual inline EConnectionState GetState();

	virtual bool ProcessHandshake();

	virtual bool ProcessLicenseCheck();

	virtual bool ProcessConnectCmd(const TravelPayload& Payload);

	virtual bool SendHandshakeResponse(EConnectionProtocol Response);

	virtual bool SendLicenseResponse(const TravelPayload& Payload, ETravelResponse Response);

	virtual void ProcessForwardData();

	virtual bool CanOperate(SOCKET Socket, EOperationType Operation);

protected:
	SOCKADDR_IN Addr;
	SOCKET		SockHandle;
	std::string Guid;

	SOCKADDR_IN TransportAddr;
	SOCKET		TransportSockHandle;

	EConnectionState State;
};

#endif // !CLIENT_SOCKET_H
