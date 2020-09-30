#include "ProxyContext.h"
#include "EasyLog.h"
#include "BufferReader.h"
#include "ProxyServer.h"

#include "event.h"
#include "event2/util.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>

ProxyContext::ProxyContext()
	: State(EConnectionState::WaitHandShake)
	, ClientEvent(nullptr)
	, TransportEvent(nullptr)
{

}

ProxyContext::~ProxyContext()
{

}

bool ProxyContext::operator==(const ProxyContext& Other) const
{
	return (ClientEvent == Other.ClientEvent && TransportEvent == Other.TransportEvent);
}

bool ProxyContext::IsValid()
{
	return (ClientEvent != nullptr || TransportEvent != nullptr);
}

EConnectionState ProxyContext::GetState()
{
	return State;
}


void ProxyContext::SetClientEvent(bufferevent* InEvent)
{
	ClientEvent = InEvent;
}

bufferevent* ProxyContext::GetClientEvent()
{
	return ClientEvent;
}

bufferevent* ProxyContext::GetTransportEvent()
{
	return TransportEvent;
}

void ProxyContext::ProcessWaitHandshake()
{
	LOG(Log, "[Connection: %d]Processing handshake.", bufferevent_getfd(ClientEvent));

	evbuffer* inBuffer = bufferevent_get_input(ClientEvent);
	size_t transportBufferSize = evbuffer_get_length(inBuffer);

	std::vector<char> requestBuffer;
	requestBuffer.resize(transportBufferSize);
	evbuffer_remove(inBuffer, requestBuffer.data(), transportBufferSize);

	BufferReader reader(requestBuffer.data(), static_cast<int>(transportBufferSize));

	HandshakePacket packet;
	reader.Serialize(&packet.Version, 1);
	reader.Serialize(&packet.MethodNum, 1);

	packet.MethodList.resize(packet.MethodNum);
	reader.Serialize(packet.MethodList.data(), packet.MethodNum);

	if (packet.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %d]Wrong protocol version.", bufferevent_getfd(ClientEvent));
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	if (packet.MethodNum < 1) {
		LOG(Warning, "[Connection: %d]Wrong method length.", bufferevent_getfd(ClientEvent));
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	bool bFoundProtocol = false;

	for (const EConnectionProtocol& protocol : packet.MethodList)
	{
		if (protocol == EConnectionProtocol::Non_auth) {
			bFoundProtocol = true;
		}
	}

	if (!bFoundProtocol) {
		LOG(Warning, "[Connection: %d]Only support non-auth protocol now.", bufferevent_getfd(ClientEvent));
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	State = EConnectionState::WaitLicense;
	SendHandshakeResponse(EConnectionProtocol::Non_auth);
}

void ProxyContext::ProcessWaitLicense()
{
	LOG(Log, "[Connection: %d]Processing wait license.", bufferevent_getfd(ClientEvent));

	evbuffer* inBuffer = bufferevent_get_input(ClientEvent);
	size_t transportBufferSize = evbuffer_get_length(inBuffer);

	std::vector<char> requestBuffer;
	requestBuffer.resize(transportBufferSize);
	evbuffer_remove(inBuffer, requestBuffer.data(), transportBufferSize);

	BufferReader reader(requestBuffer.data(), static_cast<int>(transportBufferSize));

	reader.Serialize(&LicensePayload.Version, 1);

	if (LicensePayload.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %d]Wrong protocol version.", bufferevent_getfd(ClientEvent));
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::GeneralFailure);
		return;
	}

	reader.Serialize(&LicensePayload.Cmd, 1);
	reader.Serialize(&LicensePayload.Reserved, 1);

	if (LicensePayload.Reserved != 0x00) {
		LOG(Warning, "[Connection: %d]Wrong reserved field value.", bufferevent_getfd(ClientEvent));
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::GeneralFailure);
		return;
	}

	LicensePayload.DestPort.resize(2);

	reader.Serialize(&LicensePayload.AddressType, 1);
	switch (LicensePayload.AddressType)
	{
	case EAddressType::IPv4:
	{
		LicensePayload.DestAddr.resize(4);
		reader.Serialize(LicensePayload.DestAddr.data(), 4);
		reader.Serialize(LicensePayload.DestPort.data(), 2);
		break;
	}
	case EAddressType::IPv6:
	{
		LicensePayload.DestAddr.resize(16);
		reader.Serialize(LicensePayload.DestAddr.data(), 16);
		reader.Serialize(LicensePayload.DestPort.data(), 2);
		break;
	}
	case EAddressType::DomainName:
	{
		int nameLen(0);
		reader.Serialize(&nameLen, 1);
		LicensePayload.DestAddr.resize(nameLen);

		reader.Serialize(LicensePayload.DestAddr.data(), nameLen);
		reader.Serialize(LicensePayload.DestPort.data(), 2);

		LicensePayload.DestAddr.push_back(0x00);
		break;
	}
	default:
		LOG(Warning, "[Connection: %d]Wrong address type.", bufferevent_getfd(ClientEvent));
		return;
	}

	switch (LicensePayload.Cmd)
	{
	case ECommandType::Connect:
	{
		if (!ProcessConnectCmd()) {
			State = EConnectionState::LicenseError;
			return;
		}

		State = EConnectionState::Connected;
		SendLicenseResponse(ETravelResponse::Succeeded);
		break;
	}
	
	case ECommandType::UDP:
	{
		if (!ProcessUDPCmd()) {
			State = EConnectionState::LicenseError;
			SendLicenseResponse(ETravelResponse::CmdNotSupported);
			return;
		}
		State = EConnectionState::UDPAssociate;
		SendLicenseResponse(ETravelResponse::Succeeded);
		break;
	}
	case ECommandType::Bind:
	default:
		LOG(Warning, "[Connection: %d]Not supported command.", bufferevent_getfd(ClientEvent));
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::CmdNotSupported);
		return;
	}
}

bool ProxyContext::ProcessConnectCmd()
{
	if (TransportEvent != nullptr) {
		LOG(Warning, "[Connection: %d]Processing travel.", bufferevent_getfd(ClientEvent));
		return SendLicenseResponse(ETravelResponse::ConnectionRefused);
	}

	SOCKADDR_IN destAddr;
	std::memset(&destAddr, 0, sizeof(destAddr));
	std::memcpy(&destAddr.sin_port, LicensePayload.DestPort.data(), 2);
	switch (LicensePayload.AddressType)
	{
	case EAddressType::IPv4:
	{
		destAddr.sin_family = AF_INET;

		std::memcpy(&destAddr.sin_addr, LicensePayload.DestAddr.data(), 4);
		break;
	}
	case EAddressType::DomainName:
	{
		destAddr.sin_family = AF_INET;

		ADDRINFO info, *result;
		std::memset(&info, 0, sizeof(ADDRINFO));
		info.ai_socktype = SOCK_STREAM;
		info.ai_family = AF_INET;

		int error = getaddrinfo(LicensePayload.DestAddr.data(), nullptr, &info, &result);
		if (error != 0) {
			LOG(Warning, "[Connection: %d]Convert hostname to ip address failed, err: %s.", bufferevent_getfd(ClientEvent), gai_strerrorA(error));
			return SendLicenseResponse(ETravelResponse::HostUnreachable);
		}

		destAddr.sin_addr = ((SOCKADDR_IN*)(result->ai_addr))->sin_addr;

		freeaddrinfo(result);

		break;
	}
	case EAddressType::IPv6:
	{
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::AddrNotSupported);
		break;
	}
	}


	std::shared_ptr<ProxyServer> server = ProxyServer::Get();
	event_base* base = server->GetEventHandle();
	TransportEvent = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(TransportEvent, ProxyServer::StaticOnSocketReadable, ProxyServer::StaticOnSocketWritable, ProxyServer::StaticOnRecvEvent, this);
	bufferevent_enable(TransportEvent, EV_READ | EV_WRITE);

	if (bufferevent_socket_connect(TransportEvent, (SOCKADDR*)&destAddr, sizeof(destAddr)) != 0) {
		LOG(Error, "[Connection: %d]Connect to destination server failure, code: %d.", bufferevent_getfd(ClientEvent), EVUTIL_SOCKET_ERROR());
		return SendLicenseResponse(ETravelResponse::NetworkUnreachable);
	}

	LOG(Log, "[Connection: %d]Connect to destination server succeeded.", bufferevent_getfd(ClientEvent));
	return SendLicenseResponse(ETravelResponse::Succeeded);
}

bool ProxyContext::ProcessUDPCmd()
{
	return false;
}

bool ProxyContext::SendHandshakeResponse(EConnectionProtocol Response)
{
	HandshakeResponse response;
	response.Version = ESocksVersion::Socks5;
	response.Method = Response;

	std::vector<char> responseData;
	responseData.push_back(static_cast<char>(response.Version));
	responseData.push_back(static_cast<char>(response.Method));

	LOG(Log, "[Connection: %d]Handshake response data send succeeded.", bufferevent_getfd(ClientEvent));

	return bufferevent_write(ClientEvent, responseData.data(), responseData.size()) == 0;
}

bool ProxyContext::SendLicenseResponse(ETravelResponse Response)
{
	if (ClientEvent == nullptr) {
		return false;
	}

	TravelReply reply;
	reply.Version = LicensePayload.Version;
	reply.Reply = Response;
	reply.Reserved = 0x00;
	reply.AddressType = LicensePayload.AddressType;
	reply.BindAddress = LicensePayload.DestAddr;
	reply.BindAddress.reserve(reply.BindAddress.size() - 1);
	reply.BindPort = LicensePayload.DestPort;

	std::vector<char> replyData;
	replyData.push_back(static_cast<char>(reply.Version));
	replyData.push_back(static_cast<char>(reply.Reply));
	replyData.push_back(static_cast<char>(reply.Reserved));
	replyData.push_back(static_cast<char>(reply.AddressType));
	if (LicensePayload.AddressType == EAddressType::DomainName) {
		replyData.push_back(static_cast<char>(reply.BindAddress.size()));
	}
	replyData.insert(replyData.end(), reply.BindAddress.begin(), reply.BindAddress.end());
	replyData.insert(replyData.end(), reply.BindPort.begin(), reply.BindPort.end());

	return bufferevent_write(ClientEvent, replyData.data(), replyData.size()) == 0;
}

void ProxyContext::ProcessForwardData(bufferevent* InEvent)
{
	if (ClientEvent == nullptr || TransportEvent == nullptr) {
		return;
	}

	switch (State)
	{
	case EConnectionState::Connected:
	{
		int sendState = 0;

		if (InEvent == ClientEvent) {

			evbuffer* clientBuffer = bufferevent_get_input(ClientEvent);
			size_t clientBufferSize = evbuffer_get_length(clientBuffer);
			if (clientBufferSize > 0) {
				LOG(Log, "[Connection: %d]Recv %dbytes data from client.", bufferevent_getfd(ClientEvent), clientBufferSize);
				sendState = bufferevent_write_buffer(TransportEvent, clientBuffer);
				if (sendState != 0) {
					LOG(Error, "[Connection: %d]Can't sent %dbytes from client to server.", bufferevent_getfd(ClientEvent), clientBufferSize);
				}
				else {
					LOG(Log, "[Connection: %d]Sent %dbytes from client to server.", bufferevent_getfd(ClientEvent), clientBufferSize);
				}
			}

		}
		else if (InEvent == TransportEvent) {
			evbuffer* serverBuffer = bufferevent_get_input(TransportEvent);
			size_t serverBufferSize = evbuffer_get_length(serverBuffer);
			if (serverBufferSize > 0) {
				LOG(Log, "[Connection: %d]Recv %dbytes data from server.", bufferevent_getfd(TransportEvent), serverBufferSize);
				sendState = bufferevent_write_buffer(ClientEvent, serverBuffer);
				if (sendState != 0) {
					LOG(Error, "[Connection: %d]Can't sent %dbytes from server to client.", bufferevent_getfd(TransportEvent), serverBufferSize);
				}
				else {
					LOG(Log, "[Connection: %d]Sent %dbytes from server to client.", bufferevent_getfd(TransportEvent), serverBufferSize);
				}
			}
		}
		break;
	}
	case EConnectionState::UDPAssociate:
	{
		// TODO: Add UDP associate implementions
		break;
	}
	}
	
}

void ProxyContext::OnSocketReadable(bufferevent* InEvent)
{
	switch (State)
	{
	case EConnectionState::WaitHandShake:
		ProcessWaitHandshake();
		break;
	case EConnectionState::WaitLicense:
		ProcessWaitLicense();
		break;
	case EConnectionState::Connected:
	case EConnectionState::UDPAssociate:
		ProcessForwardData(InEvent);
		break;
	default:
		break;
	}
}

void ProxyContext::OnSocketSent(bufferevent* InEvent)
{

}

bool ProxyContext::BeforeDestroyContext(bufferevent* InEvent)
{
	if (InEvent == ClientEvent) {
		ClientEvent = nullptr;
		bufferevent_free(InEvent);
	}
	else if (InEvent == TransportEvent) {
		TransportEvent = nullptr;
		bufferevent_free(InEvent);
	}
	else {
		LOG(Error, "The connection %d is not handled by this context.", bufferevent_getfd(InEvent));
	}

	return !IsValid();
}
