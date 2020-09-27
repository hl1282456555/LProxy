#include "ClientSocket.h"
#include "EasyLog.h"
#include "BufferReader.h"

#include <WS2tcpip.h>

ClientSocket::ClientSocket(SOCKADDR_IN InAddr, SOCKET InHandle)
	: Addr(InAddr)
	, SockHandle(InHandle)
	, Guid(MiscHelper::NewGuid(64))
	, bRequestClose(false)
	, State(EConnectionState::None)
{

}

ClientSocket::~ClientSocket()
{
	if (SockHandle == INVALID_SOCKET) {
		return;
	}

	closesocket(SockHandle);
}

bool ClientSocket::InitConnection()
{
	if (SockHandle == INVALID_SOCKET) {
		LOG(Log, "[Client: %s]Can't init connection with INVALID_SOCKET.", Guid.c_str());
		return false;
	}

	if (!ProcessHandshake()) {
		LOG(Warning, "[Client: %s]Try to process handshake with client failed.", Guid.c_str());
		HandshakeResponse response;
		response.Version = static_cast<char>(ESocksVersion::Socks5);
		response.Method = static_cast<char>(EConnectionProtocol::Error);
		if (send(SockHandle, (const char*)&response, sizeof(response), 0) == SOCKET_ERROR) {
			LOG(Warning, "[Client: %s]Send error response failed, code: %d", WSAGetLastError());
		}
		return false;
	}

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
		return false;
	}

	HandshakePacket packet;
	packet.Version = static_cast<ESocksVersion>(handshakeBuffer[0]);
	packet.MethodNum = handshakeBuffer[1];
	packet.MethodList.assign(handshakeBuffer + 2, handshakeBuffer + packet.MethodNum + 1);

	if (packet.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Client: %s]Wrong protocol version.", Guid.c_str());
		return false;
	}

	if (packet.MethodNum < 1) {
		LOG(Warning, "[Client: %s]Wrong method length.", Guid.c_str());
		return false;
	}

	bool bFoundProtocol = false;

	for (const char& protocol : packet.MethodList)
	{
		if (protocol == static_cast<char>(EConnectionProtocol::Non_auth)) {
			bFoundProtocol = true;
		}
	}

	if (!bFoundProtocol) {
		LOG(Warning, "[Client: %s]Only support non-auth protocol now.", Guid.c_str());
		return false;
	}

	HandshakeResponse response;
	response.Version = static_cast<char>(ESocksVersion::Socks5);
	response.Method = static_cast<char>(EConnectionProtocol::Non_auth);

	if (send(SockHandle, (const char*)&response, sizeof(response), 0) == SOCKET_ERROR) {
		LOG(Warning, "[Client: %s]Send choiced mesthod response failed, code: %d", Guid.c_str(), WSAGetLastError());
		return false;
	}

	return true;
}

bool ClientSocket::ProcessLicenseCheck()
{
	LOG(Log, "[Client: %s]Processing travel.", Guid.c_str());
	static const int travelBufferSize = 4096;
	char requestBuffer[travelBufferSize] = { 0 };

	int result = recv(SockHandle, requestBuffer, travelBufferSize, 0);
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

		payload.DestAddr.push_back('0x00');
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
		return ProcessConnectCmd(payload);
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
	SOCKET destSock = socket(AF_INET, SOCK_STREAM, 0);
	if (destSock == INVALID_SOCKET) {
		return false;
	}

	SOCKADDR_IN serverAddr;
	std::memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = 0;
	InetPtonA(AF_INET, "localhost", &serverAddr.sin_addr.S_un);

	if (bind(destSock, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		return false;
	}

	SOCKADDR_IN destAddr;
	std::memset(&destAddr, 0, sizeof(destAddr));
	destAddr.sin_family = AF_INET;
	std::memcpy(&destAddr.sin_port, Payload.DestPort.data(), 2 * sizeof(char));
	InetPtonA(AF_INET, Payload.DestAddr.data(), &destAddr.sin_addr.S_un);

	if (connect(destSock, (SOCKADDR*)&destAddr, sizeof(SOCKADDR) == SOCKET_ERROR)) {
		return false;
	}

	LOG(Log, "[Client: %s]Connect to destination server succeeded.", Guid.c_str());

	return true;
}
