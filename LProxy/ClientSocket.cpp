#include "ClientSocket.h"
#include "EasyLog.h"
#include "BufferReader.h"
#include "ProxyServer.h"

#include <WS2tcpip.h>
#include <vector>

ClientSocket::ClientSocket(SOCKADDR_IN InAddr, SOCKET InHandle)
	: Addr(InAddr)
	, SockHandle(InHandle)
	, TransportAddr()
	, TransportSockHandle(INVALID_SOCKET)
	, Guid(MiscHelper::NewGuid(16))
	, bRequestClose(false)
	, State(EConnectionState::None)
{

}

ClientSocket::~ClientSocket()
{
	if (SockHandle != INVALID_SOCKET) {
		closesocket(SockHandle);
		SockHandle = INVALID_SOCKET;
	}

	if (TransportSockHandle != INVALID_SOCKET) {
		closesocket(TransportSockHandle);
		TransportSockHandle = INVALID_SOCKET;
	}

}

bool ClientSocket::InitConnection()
{
	if (SockHandle == INVALID_SOCKET) {
		LOG(Warning, "[Client: %s]Can't init connection with INVALID_SOCKET.", Guid.c_str());
		return false;
	}

	if (!ProcessHandshake()) {
		LOG(Warning, "[Client: %s]Try to process handshake with client failed.", Guid.c_str());
		return false;
	}

	if (!ProcessLicenseCheck()) {
		LOG(Warning, "[Client: %s]Try to process license check failed.", Guid.c_str());
		return false;
	}

	LOG(Log, "[Client: %s]Data travel startup.", Guid.c_str());

	std::thread clientThread(
	[&]()
	{
		static const int transportBufferSize = 4096;
		char transportBuffer[transportBufferSize];

		while (!bRequestClose && SockHandle != INVALID_SOCKET && TransportSockHandle != INVALID_SOCKET)
		{
			int transportBytes = 0;

			std::memset(transportBuffer, 0, transportBufferSize * sizeof(char));
			int result = recv(SockHandle, transportBuffer, transportBufferSize, 0);
			if (result == SOCKET_ERROR) {
				LOG(Warning, "[Client: %s]Recv data from client failed.", Guid.c_str());
				break;
			}

			transportBytes += result;

			result = send(TransportSockHandle, transportBuffer, result, 0);
			if (result == SOCKET_ERROR) {
				LOG(Warning, "[Client: %s]Send data to destination server failed.", Guid.c_str());
				break;
			}

			std::memset(transportBuffer, 0, transportBufferSize * sizeof(char));
			result = recv(TransportSockHandle, transportBuffer, transportBufferSize, 0);
			if (result == SOCKET_ERROR) {
				LOG(Warning, "[Client: %s]Recv data from destination server failed.", Guid.c_str());
				break;
			}

			transportBytes += result;

			result = send(SockHandle, transportBuffer, result, 0);
			if (result == SOCKET_ERROR) {
				LOG(Warning, "[Client: %s]Send data to client failed.", Guid.c_str());
				break;
			}

			LOG(Log, "[Client: %s]Transported buffer size: %d", transportBytes);
		}

		std::shared_ptr<ProxyServer> proxyServer = ProxyServer::Get();
		proxyServer->CloseClient(std::shared_ptr<ClientSocket>(this));
	});

	clientThread.detach();

	return true;
}

void ClientSocket::Close()
{
	bRequestClose = true;
	State = EConnectionState::RequestClose;
}

bool ClientSocket::operator==(const ClientSocket& Other) const
{
	return Guid == Other.Guid;
}

bool ClientSocket::ProcessHandshake()
{
	LOG(Log, "[Client: %s]Processing handshake.", Guid.c_str());
	static const int handshakeBufferSize = 1 + 1 + 255;
	char handshakeBuffer[handshakeBufferSize];

	int result = recv(SockHandle, handshakeBuffer, handshakeBufferSize, 0);
	if (result == SOCKET_ERROR || result < 3) {
		LOG(Warning, "[Client: %s]Recv data from client failed, code: %d", Guid.c_str(), WSAGetLastError());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	BufferReader reader(handshakeBuffer, result);

	HandshakePacket packet;
	reader.Serialize(&packet.Version, 1);
	reader.Serialize(&packet.MethodNum, 1);

	packet.MethodList.reserve(packet.MethodNum);
	reader.Serialize(packet.MethodList.data(), packet.MethodNum);

	if (packet.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Client: %s]Wrong protocol version.", Guid.c_str());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	if (packet.MethodNum < 1) {
		LOG(Warning, "[Client: %s]Wrong method length.", Guid.c_str());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	bool bFoundProtocol = false;

	for (const EConnectionProtocol& protocol : packet.MethodList)
	{
		if (protocol == EConnectionProtocol::Non_auth) {
			bFoundProtocol = true;
		}
	}

	if (!bFoundProtocol) {
		LOG(Warning, "[Client: %s]Only support non-auth protocol now.", Guid.c_str());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	return SendHandshakeResponse(EConnectionProtocol::Non_auth);
}

bool ClientSocket::ProcessLicenseCheck()
{
	LOG(Log, "[Client: %s]Processing transport.", Guid.c_str());
	static const int transportBufferSize = 4096;
	char requestBuffer[transportBufferSize] = { 0 };

	int result = recv(SockHandle, requestBuffer, transportBufferSize, 0);
	if (result == SOCKET_ERROR) {
		LOG(Warning, "[Client: %s]", Guid.c_str());
		return false;
	}

	BufferReader reader(requestBuffer, result);

	TravelPayload payload;
	reader.Serialize(&payload.Version, 1);

	if (payload.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Client: %s]Wrong protocol version.", Guid.c_str());
		return false;
	}

	reader.Serialize(&payload.Cmd, 1);
	reader.Serialize(&payload.Reserved, 1);

	if (payload.Reserved != 0x00) {
		LOG(Warning, "[Client: %s]Wrong reserved field value.");
		return false;
	}

	payload.DestPort.reserve(2);

	reader.Serialize(&payload.AddressType, 1);
	switch (payload.AddressType)
	{
	case EAddressType::IPv4:
	{
		payload.DestAddr.reserve(4);
		reader.Serialize(&payload.DestAddr, 4);
		reader.Serialize(&payload.DestPort, 2);
		break;
	}
	case EAddressType::IPv6:
	{
		payload.DestAddr.reserve(16);
		reader.Serialize(payload.DestAddr.data(), 16);
		reader.Serialize(payload.DestPort.data(), 2);
		break;
	}
	case EAddressType::DomainName:
	{
		int nameLen(0);
		reader.Serialize(&nameLen, 1);
		payload.DestAddr.reserve(nameLen);

		reader.Serialize(payload.DestAddr.data(), nameLen);
		reader.Serialize(payload.DestPort.data(), 2);

		payload.DestAddr.push_back(0x00);
		break;
	}
	default:
		LOG(Warning, "[Client: %s]Wrong address type.", Guid.c_str());
		return false;
	}

	switch (payload.Cmd)
	{
	case ECommandType::Connect:
	{
		if (!ProcessConnectCmd(payload)) {
			return false;
		}
		break;
	}
	case ECommandType::Bind:
	case ECommandType::UDP:
	default:
		LOG(Warning, "[Client: %s]Not supported command.");
		return false;
	}

	return true;
}

bool ClientSocket::ProcessConnectCmd(const TravelPayload& Payload)
{
	if (TransportSockHandle != INVALID_SOCKET) {
		LOG(Warning, "[Client: %s]Processing travel.", Guid.c_str());
		return false;
	}

	TransportSockHandle = socket(AF_INET, SOCK_STREAM, 0);
	if (TransportSockHandle == INVALID_SOCKET) {
		return false;
	}

	std::memset(&TransportAddr, 0, sizeof(TransportAddr));
	TransportAddr.sin_family = AF_INET;
	TransportAddr.sin_port = 0;
	InetPtonA(AF_INET, "localhost", &TransportAddr.sin_addr.S_un);

	if (bind(TransportSockHandle, (SOCKADDR*)&TransportAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		return false;
	}

	SOCKADDR_IN destAddr;
	std::memset(&destAddr, 0, sizeof(destAddr));
	destAddr.sin_family = AF_INET;
	std::memcpy(&destAddr.sin_port, Payload.DestPort.data(), 2 * sizeof(char));
	InetPtonA(AF_INET, Payload.DestAddr.data(), &destAddr.sin_addr.S_un);

	if (connect(TransportSockHandle, (SOCKADDR*)&destAddr, sizeof(SOCKADDR) == SOCKET_ERROR)) {
		return false;
	}

	LOG(Log, "[Client: %s]Connect to destination server succeeded.", Guid.c_str());

	return SendLicenseResponse(Payload, ETravelResponse::Succeeded);
}

bool ClientSocket::SendHandshakeResponse(EConnectionProtocol Response)
{
	HandshakeResponse response;
	response.Version = ESocksVersion::Socks5;
	response.Method = Response;

	std::vector<char> responseData;
	responseData.push_back(static_cast<char>(response.Version));
	responseData.push_back(static_cast<char>(response.Method));

	if (send(SockHandle, responseData.data(), responseData.size(), 0) == SOCKET_ERROR) {
		LOG(Warning, "[Client: %s]Send handshake response failed.", Guid.c_str());
		return false;
	}

	return true;
}

bool ClientSocket::SendLicenseResponse(const TravelPayload& Payload, ETravelResponse Response)
{
	if (SockHandle == INVALID_SOCKET) {
		return false;
	}

	TravelReply reply;
	reply.Version = Payload.Version;
	reply.Reply = Response;
	reply.Reserved = 0x00;
	reply.AddressType = Payload.AddressType;
	reply.BindAddress = Payload.DestAddr;
	reply.BindAddress.reserve(reply.BindAddress.size() - 1);
	reply.BindPort = Payload.DestPort;

	std::vector<char> replyData;
	replyData.push_back(static_cast<char>(reply.Version));
	replyData.push_back(static_cast<char>(reply.Reply));
	replyData.push_back(static_cast<char>(reply.Reserved));
	replyData.push_back(static_cast<char>(reply.AddressType));
	replyData.insert(replyData.end(), reply.BindAddress.begin(), reply.BindAddress.end());
	replyData.insert(replyData.end(), reply.BindPort.begin(), reply.BindPort.end());

	if (send(SockHandle, replyData.data(), replyData.size(), 0) == SOCKET_ERROR) {
		LOG(Warning, "[Client: %s]Send response of license check failed.", Guid.c_str());
		return false;
	}

	return true;
}
