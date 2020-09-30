#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include "ProxyStructures.h"

class ProxyContext
{
public:
	ProxyContext();
	virtual ~ProxyContext();

	bool operator==(const ProxyContext& Other) const;

	virtual inline EConnectionState GetState();

	virtual void ProcessWaitHandshake();

	virtual void ProcessWaitLicense();

	virtual bool ProcessConnectCmd();

	virtual bool ProcessUDPCmd();

	virtual bool SendHandshakeResponse(EConnectionProtocol Response);

	virtual bool SendLicenseResponse(ETravelResponse Response);

	virtual void ProcessForwardData(bufferevent* InEvent);

protected:
	SOCKET	Client;
	SOCKET	Destination;

	TravelPayload LicensePayload;

	EConnectionState State;
};

#endif // !CLIENT_SOCKET_H
