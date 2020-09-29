#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#include "ProxyStructures.h"

#include "event2/bufferevent.h"

class ProxyContext
{
public:
	ProxyContext();
	virtual ~ProxyContext();

	bool operator==(const ProxyContext& Other) const;

	virtual inline bool IsValid();

	virtual inline EConnectionState GetState();

	virtual inline void SetClientEvent(bufferevent* InEvent);
	virtual inline bufferevent* GetClientEvent();

	virtual inline bufferevent* GetTransportEvent();

	virtual void ProcessWaitHandshake();

	virtual void ProcessWaitLicense();

	virtual bool ProcessConnectCmd();

	virtual bool SendHandshakeResponse(EConnectionProtocol Response);

	virtual bool SendLicenseResponse(ETravelResponse Response);

	virtual void ProcessForwardData();

	virtual void OnSocketReadable(bufferevent* InEvent);

	virtual void OnSocketWritable(bufferevent* InEvent);

	virtual bool BeforeDestroyContext(bufferevent* InEvent);

protected:
	bufferevent* ClientEvent;
	bufferevent* TransportEvent;

	TravelPayload LicensePayload;

	EConnectionState State;
	EConnectionProtocol HandshakeState;
	ETravelResponse	LicenseState;
};

#endif // !CLIENT_SOCKET_H
