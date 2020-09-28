#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include "ProxyStructures.h"

#include <WinSock2.h>
#include <string>
#include <vector>
#include <chrono>

class ClientSocket
{
public:
	ClientSocket(SOCKADDR_IN InAddr, SOCKET	InHandle);
	virtual ~ClientSocket();

	virtual void Close();

	bool operator==(const ClientSocket& Other) const;

	virtual inline std::string GetGuid();

	virtual inline EConnectionState GetState();

	virtual inline std::chrono::system_clock::time_point GetStartTime();

	virtual inline void SetStartTime(const std::chrono::system_clock::time_point& InTime);

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

	EConnectionState State;

	std::chrono::system_clock::time_point StartTime;
};

#endif // !CLIENT_SOCKET_H
