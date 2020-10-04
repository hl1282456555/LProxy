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

	virtual bool SendLicenseResponse(ETravelResponse Response);

	virtual void ProcessForwardData();

protected:

	virtual bool TransportTraffic();

	virtual bool TransportTraffic(SOCKET Source, SOCKET Target);

	virtual std::string GetCurrentThreadId();

	virtual std::string GetTravelResponseName(ETravelResponse Response);

protected:
	SOCKET	Client;
	SOCKET	Destination;

	TravelPayload LicensePayload;

	EConnectionState State;
};

#endif // !CLIENT_SOCKET_H
