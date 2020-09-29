#include "ProxyContext.h"
#include "EasyLog.h"
#include "BufferReader.h"
#include "ProxyServer.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>

ProxyContext::ProxyContext(SOCKADDR_IN InAddr, SOCKET InHandle)
	: Addr(InAddr)
	, SockHandle(InHandle)
	, TransportAddr()
	, TransportSockHandle(INVALID_SOCKET)
	, Guid(MiscHelper::NewGuid(8))
	, State(EConnectionState::None)
{

}

ProxyContext::~ProxyContext()
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

void ProxyContext::Close()
{
	State = EConnectionState::RequestClose;
}

bool ProxyContext::operator==(const ProxyContext& Other) const
{
	return Guid == Other.Guid;
}

std::string ProxyContext::GetGuid()
{
	return Guid;
}

EConnectionState ProxyContext::GetState()
{
	return State;
}

bool ProxyContext::ProcessHandshake()
{
	LOG(Log, "[Connection: %s]Processing handshake.", Guid.c_str());

	static const int handshakeBufferSize = 1 + 1 + 255;
	char handshakeBuffer[handshakeBufferSize];

	int result = recv(SockHandle, handshakeBuffer, handshakeBufferSize, 0);
	if (result == SOCKET_ERROR || result < 3) {
		LOG(Warning, "[Connection: %s]Recv data from client failed, code: %d", Guid.c_str(), WSAGetLastError());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	BufferReader reader(handshakeBuffer, result);

	HandshakePacket packet;
	reader.Serialize(&packet.Version, 1);
	reader.Serialize(&packet.MethodNum, 1);

	packet.MethodList.resize(packet.MethodNum);
	reader.Serialize(packet.MethodList.data(), packet.MethodNum);

	if (packet.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %s]Wrong protocol version.", Guid.c_str());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	if (packet.MethodNum < 1) {
		LOG(Warning, "[Connection: %s]Wrong method length.", Guid.c_str());
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
		LOG(Warning, "[Connection: %s]Only support non-auth protocol now.", Guid.c_str());
		SendHandshakeResponse(EConnectionProtocol::Error);
		return false;
	}

	State = EConnectionState::Handshark;

	return SendHandshakeResponse(EConnectionProtocol::Non_auth);
}

bool ProxyContext::ProcessLicenseCheck()
{
	LOG(Log, "[Connection: %s]Processing transport.", Guid.c_str());

	static const int transportBufferSize = 4096;
	char requestBuffer[transportBufferSize] = { 0 };

	int result = recv(SockHandle, requestBuffer, transportBufferSize, 0);
	if (result == SOCKET_ERROR) {
		LOG(Warning, "[Connection: %s]Can't recv data from connection, code: %d", Guid.c_str(), WSAGetLastError());
		return false;
	}

	BufferReader reader(requestBuffer, result);
	
	TravelPayload payload;
	reader.Serialize(&payload.Version, 1);

	if (payload.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %s]Wrong protocol version.", Guid.c_str());
		SendLicenseResponse(payload, ETravelResponse::RulesetNotAllowed);
		return false;
	}

	reader.Serialize(&payload.Cmd, 1);
	reader.Serialize(&payload.Reserved, 1);

	if (payload.Reserved != 0x00) {
		LOG(Warning, "[Connection: %s]Wrong reserved field value.");
		SendLicenseResponse(payload, ETravelResponse::GeneralFailure);
		return false;
	}

	payload.DestPort.resize(2);

	reader.Serialize(&payload.AddressType, 1);
	switch (payload.AddressType)
	{
	case EAddressType::IPv4:
	{
		payload.DestAddr.resize(4);
		reader.Serialize(payload.DestAddr.data(), 4);
		reader.Serialize(payload.DestPort.data(), 2);
		break;
	}
	case EAddressType::IPv6:
	{
		payload.DestAddr.resize(16);
		reader.Serialize(payload.DestAddr.data(), 16);
		reader.Serialize(payload.DestPort.data(), 2);
		break;
	}
	case EAddressType::DomainName:
	{
		int nameLen(0);
		reader.Serialize(&nameLen, 1);
		payload.DestAddr.resize(nameLen);

		reader.Serialize(payload.DestAddr.data(), nameLen);
		reader.Serialize(payload.DestPort.data(), 2);

		payload.DestAddr.push_back(0x00);
		break;
	}
	default:
		LOG(Warning, "[Connection: %s]Wrong address type.", Guid.c_str());
		return false;
	}

	State = EConnectionState::CheckLicense;

	switch (payload.Cmd)
	{
	case ECommandType::Connect:
	{
		if (!ProcessConnectCmd(payload)) {
			SendLicenseResponse(payload, ETravelResponse::GeneralFailure);
			return false;
		}
		break;
	}
	case ECommandType::Bind:
	case ECommandType::UDP:
	default:
		LOG(Warning, "[Connection: %s]Not supported command.", Guid.c_str());
		SendLicenseResponse(payload, ETravelResponse::CmdNotSupported);
		return false;
	}

	return SendLicenseResponse(payload, ETravelResponse::Succeeded);;
}

bool ProxyContext::ProcessConnectCmd(const TravelPayload& Payload)
{
	if (TransportSockHandle != INVALID_SOCKET) {
		LOG(Warning, "[Connection: %s]Processing travel.", Guid.c_str());
		SendLicenseResponse(Payload, ETravelResponse::GeneralFailure);
		return false;
	}

	TransportSockHandle = socket(AF_INET, SOCK_STREAM, 0);
	if (TransportSockHandle == INVALID_SOCKET) {
		LOG(Warning, "[Connection: %s]Create a new socket for transport failed, code: %d", Guid.c_str(), WSAGetLastError());
		SendLicenseResponse(Payload, ETravelResponse::GeneralFailure);
		return false;
	}

	// Make client socket enable non-blocking method
	unsigned long sockMode(1);
	if (ioctlsocket(TransportSockHandle, FIONBIO, &sockMode) != NO_ERROR) {
		LOG(Warning, "[Connection: %s]Set non-blocking method failed.", Guid.c_str());
	}

	std::memset(&TransportAddr, 0, sizeof(TransportAddr));
	TransportAddr.sin_family = AF_INET;
	TransportAddr.sin_port = 0;
	InetPtonA(AF_INET, "localhost", &TransportAddr.sin_addr);

	if (bind(TransportSockHandle, (SOCKADDR*)&TransportAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		LOG(Warning, "[Connection: %s]Bind address for transport socket failed, code: %d", Guid.c_str(), WSAGetLastError());
		SendLicenseResponse(Payload, ETravelResponse::GeneralFailure);
		return false;
	}

	SOCKADDR_IN destAddr;
	std::memset(&destAddr, 0, sizeof(destAddr));
	std::memcpy(&destAddr.sin_port, Payload.DestPort.data(), 2);
	switch (Payload.AddressType)
	{
	case EAddressType::IPv4:
	{
		destAddr.sin_family = AF_INET;

		InetPtonA(AF_INET, Payload.DestAddr.data(), &destAddr.sin_addr);
		break;
	}
	case EAddressType::DomainName:
	{
		destAddr.sin_family = AF_INET;

		ADDRINFO info, *result;
		std::memset(&info, 0, sizeof(ADDRINFO));
		info.ai_socktype = SOCK_STREAM;
		info.ai_family = AF_INET;

		int error = getaddrinfo(Payload.DestAddr.data(), nullptr, &info, &result);
		if (error != 0) {
			LOG(Warning, "[Connection: %s]Convert hostname to ip address failed, err: %s.", Guid.c_str(), gai_strerrorA(error));
			SendLicenseResponse(Payload, ETravelResponse::HostUnreachable);
			return false;
		}

		destAddr.sin_addr = ((SOCKADDR_IN*)(result->ai_addr))->sin_addr;

		freeaddrinfo(result);

		break;
	}
	case EAddressType::IPv6:
	{
		destAddr.sin_family = AF_INET6;

		InetPtonA(AF_INET6, Payload.DestAddr.data(), &destAddr.sin_addr);
		break;
	}
	}

	connect(TransportSockHandle, (SOCKADDR*)&destAddr, sizeof(SOCKADDR));
	if (!CanOperate(TransportSockHandle, EOperationType::Write)) {
		LOG(Warning, "[Connection: %s]Connect to destination server failure, code: %d.", Guid.c_str(), WSAGetLastError());
		State = EConnectionState::RequestClose;
		return SendLicenseResponse(Payload, ETravelResponse::GeneralFailure);
	}
	

	LOG(Log, "[Connection: %s]Connect to destination server succeeded.", Guid.c_str());
	State = EConnectionState::Connected;

	return SendLicenseResponse(Payload, ETravelResponse::Succeeded);
}

bool ProxyContext::SendHandshakeResponse(EConnectionProtocol Response)
{
	HandshakeResponse response;
	response.Version = ESocksVersion::Socks5;
	response.Method = Response;

	std::vector<char> responseData;
	responseData.push_back(static_cast<char>(response.Version));
	responseData.push_back(static_cast<char>(response.Method));

	if (send(SockHandle, responseData.data(), static_cast<int>(responseData.size()), 0) == SOCKET_ERROR) {
		LOG(Warning, "[Connection: %s]Send handshake response failed.", Guid.c_str());
		return false;
	}

	LOG(Log, "[Connection: %s]Handshake response data send succeeded.", Guid.c_str());

	return true;
}

bool ProxyContext::SendLicenseResponse(const TravelPayload& Payload, ETravelResponse Response)
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
	replyData.push_back(static_cast<char>(reply.BindAddress.size()));
	replyData.insert(replyData.end(), reply.BindAddress.begin(), reply.BindAddress.end());
	replyData.insert(replyData.end(), reply.BindPort.begin(), reply.BindPort.end());

	if (send(SockHandle, replyData.data(), static_cast<int>(replyData.size()), 0) == SOCKET_ERROR) {
		LOG(Warning, "[Connection: %s]Send response of license check failed, code: %d.", Guid.c_str(), WSAGetLastError());
		return false;
	}

	return true;
}

void ProxyContext::ProcessForwardData()
{
	if (SockHandle == INVALID_SOCKET) {
		return;
	}

	int traffic = 0;

	char transportBuffer[SOCK_BUFFER_SIZE];

	FD_SET sockSet;
	FD_ZERO(&sockSet);
	FD_SET(SockHandle, &sockSet);
	FD_SET(TransportSockHandle, &sockSet);

	TIMEVAL timeout{3, 0};

	int result = select(3, &sockSet, nullptr, nullptr, &timeout);
	if (result == SOCKET_ERROR) {
		LOG(Log, "[Connection: %s]Select socket failed, code: %d.", Guid.c_str(), WSAGetLastError());
		return;
	}

	for (unsigned int index = 0; index < sockSet.fd_count; index++)
	{
		traffic = 0;
		std::memset(transportBuffer, 0, SOCK_BUFFER_SIZE);

		SOCKET tempSock = sockSet.fd_array[index];
		if (tempSock == SockHandle) {
			result = recv(SockHandle, transportBuffer, SOCK_BUFFER_SIZE, 0);
			if (result > 0) {
				traffic += result;

				result = send(TransportSockHandle, transportBuffer, result, 0);
				if (result != SOCKET_ERROR) {
					LOG(Log, "[Connection: %s]Forwarded data from client to dest: %dbytes", Guid.c_str(), traffic);
				}
			}
			else if (result == SOCKET_ERROR){
				LOG(Warning, "[Connection: %s]Recv data from client failed, code: %d", Guid.c_str(), WSAGetLastError());
				State = EConnectionState::RequestClose;
			}
		}
		else {
			result = recv(TransportSockHandle, transportBuffer, SOCK_BUFFER_SIZE, 0);
			if (result > 0) {
				traffic += result;

				result = send(SockHandle, transportBuffer, result, 0);
				if (result != SOCKET_ERROR) {
					LOG(Log, "[Connection: %s]Forwarded data from dest to client: %dbytes", Guid.c_str(), traffic);
				}
			}
			else if (result == SOCKET_ERROR) {
				LOG(Warning, "[Connection: %s]Recv data from dest failed, code: %d", Guid.c_str(), WSAGetLastError());
				State = EConnectionState::RequestClose;
			}
		}
	}
}

bool ProxyContext::CanOperate(SOCKET Socket, EOperationType Operation)
{
	FD_SET sockSet;
	TIMEVAL timeout = { 5, 0 };

	FD_ZERO(&sockSet);
	FD_SET(Socket, &sockSet);

	int result = 0;

	switch (Operation)
	{
	case EOperationType::Read:
		result = select(2, &sockSet, nullptr, nullptr, &timeout);
		break;
	case EOperationType::Write:
		result = select(2, nullptr, &sockSet, nullptr, &timeout);
		break;
	case EOperationType::Exception:
		result = select(2, nullptr, nullptr, &sockSet, &timeout);
		break;
	default:
		return false;
	}

	return (result > 0 && FD_ISSET(Socket, &sockSet));
}
