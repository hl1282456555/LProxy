#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include "ProxyStructures.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>
#include <string>

class ProxyContext
{
public:
	ProxyContext(SOCKET InClient, EConnectionState InState = EConnectionState::WaitHandShake);
	virtual ~ProxyContext();

	bool operator==(const ProxyContext& Other) const;

	virtual inline EConnectionState GetConnectionState() const;

	virtual void ProcessWaitHandshake();

	virtual void ProcessWaitLicense();

	virtual bool ProcessConnectCmd();

	virtual bool ProcessUDPCmd();

	virtual bool SendHandshakeResponse(EConnectionProtocol Response);

	virtual bool SendLicenseResponse(ETravelResponse Response, bool bTCP = true);

	virtual void ProcessForwardData();

protected:

	virtual bool TransportTraffic();

	virtual bool TransportTraffic(SOCKET Source, SOCKET Target);

	virtual bool TransportUDPTraffic();

	virtual std::string GetCurrentThreadId();

	virtual std::string GetTravelResponseName(ETravelResponse Response);

	virtual bool ParseTCPPayloadAddress();

	virtual bool ParseUDPPayloadAddress();

	virtual UDPTravelReply ParseUDPPacket(const char* buffer, int Len);

protected:
	SOCKET	Client;
	SOCKET	UDPClient;
	SOCKET	Destination;

	SOCKADDR_IN UDPClientAddr;
	SOCKADDR_IN DestAddr;

	unsigned short UDPPort;

	TravelPayload LicensePayload;

	EConnectionState State;
};

#endif // !CLIENT_SOCKET_H
