#include "ProxyContext.h"
#include "EasyLog.h"
#include "BufferReader.h"
#include "ProxyServer.h"

#include <functional>
#include <sstream>

ProxyContext::ProxyContext(SOCKET InClient, EConnectionState InState /*= EConnectionState::WaitHandshake*/)
	: State(InState)
	, Client(InClient)
{

}

ProxyContext::~ProxyContext()
{
	LOG(Log, "[Connection: %s]Connection request close, disconnected.", GetCurrentThreadId().c_str());
	if (Client != INVALID_SOCKET) {
		closesocket(Client);
		Client = INVALID_SOCKET;
	}

	if (Destination != INVALID_SOCKET) {
		closesocket(Destination);
		Destination = INVALID_SOCKET;
	}
}

bool ProxyContext::operator==(const ProxyContext& Other) const
{
	return (Client == Client && Destination == Destination);
}

EConnectionState ProxyContext::GetConnectionState() const
{
	return State;
}

void ProxyContext::ProcessWaitHandshake()
{
	LOG(Log, "[Connection: %s]Processing handshake.", GetCurrentThreadId().c_str());

	char handshakeData[TRAFFIC_BUFFER_SIZE];
	int recvResult = recv(Client, handshakeData, TRAFFIC_BUFFER_SIZE, 0);
	if (recvResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %s]Recv handshake occured some errors, code: %d", GetCurrentThreadId().c_str(), WSAGetLastError());
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	BufferReader reader(handshakeData, static_cast<int>(TRAFFIC_BUFFER_SIZE));

	HandshakePacket packet;
	reader.Serialize(&packet.Version, 1);
	reader.Serialize(&packet.MethodNum, 1);

	packet.MethodList.resize(packet.MethodNum);
	reader.Serialize(packet.MethodList.data(), packet.MethodNum);

	if (packet.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %s]Wrong protocol version.", GetCurrentThreadId().c_str());
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	if (packet.MethodNum < 1) {
		LOG(Warning, "[Connection: %s]Wrong method length.", GetCurrentThreadId().c_str());
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
		LOG(Warning, "[Connection: %s]Only support non-auth protocol now.", GetCurrentThreadId().c_str());
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	State = EConnectionState::WaitLicense;
	SendHandshakeResponse(EConnectionProtocol::Non_auth);
}

void ProxyContext::ProcessWaitLicense()
{
	LOG(Log, "[Connection: %s]Processing wait license.", GetCurrentThreadId().c_str());

	char licenseData[TRAFFIC_BUFFER_SIZE];
	int recvResult = recv(Client, licenseData, TRAFFIC_BUFFER_SIZE, 0);
	if (recvResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %s]Recv license occured some errors, code: %d", GetCurrentThreadId().c_str(), WSAGetLastError());
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	BufferReader reader(licenseData, TRAFFIC_BUFFER_SIZE);

	reader.Serialize(&LicensePayload.Version, 1);

	if (LicensePayload.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %s]Wrong protocol version.", GetCurrentThreadId().c_str());
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::GeneralFailure);
		return;
	}

	reader.Serialize(&LicensePayload.Cmd, 1);
	reader.Serialize(&LicensePayload.Reserved, 1);

	if (LicensePayload.Reserved != 0x00) {
		LOG(Warning, "[Connection: %s]Wrong reserved field value.", GetCurrentThreadId().c_str());
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
		LOG(Warning, "[Connection: %s]Wrong address type.", GetCurrentThreadId().c_str());
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
		break;
	}
	
	case ECommandType::UDP:
	{
		if (!ProcessUDPCmd()) {
			State = EConnectionState::LicenseError;
			return;
		}
		State = EConnectionState::UDPAssociate;
		break;
	}
	case ECommandType::Bind:
	default:
		LOG(Warning, "[Connection: %s]Not supported command.", GetCurrentThreadId().c_str());
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::CmdNotSupported);
		return;
	}
}

bool ProxyContext::ProcessConnectCmd()
{
	if (!ParsePayloadAddress()) {
		return false;
	}

	int connectResult = connect(Destination, (SOCKADDR*)&DestAddr, sizeof(DestAddr));
	if (connectResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %s]Connect to destination server failure, code: %d.", GetCurrentThreadId().c_str(), WSAGetLastError());
		SendLicenseResponse(ETravelResponse::NetworkUnreachable);
		return false;
	}

	LOG(Log, "[Connection: %s]Connect to destination server succeeded.", GetCurrentThreadId().c_str());
	return SendLicenseResponse(ETravelResponse::Succeeded);
}

bool ProxyContext::ProcessUDPCmd()
{
	if (!ParsePayloadAddress()) {
		return false;
	}

	TIMEVAL timeout = { 0, SOCK_TIMEOUT_MSEC };
	setsockopt(Destination, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	LOG(Log, "[Connection: %d]Connect to destination server with udp connection succeeded.", GetCurrentThreadId().c_str());

	return SendLicenseResponse(ETravelResponse::Succeeded);
}

bool ProxyContext::SendHandshakeResponse(EConnectionProtocol Response)
{
	HandshakeResponse response;
	response.Version = ESocksVersion::Socks5;
	response.Method = Response;

	std::vector<char> responseData;
	responseData.push_back(static_cast<char>(response.Version));
	responseData.push_back(static_cast<char>(response.Method));

	

	int sendResult = send(Client, responseData.data(), static_cast<int>(responseData.size()), 0);
	if (sendResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %s]Send handshake response failed, code: %d", GetCurrentThreadId().c_str(), WSAGetLastError());
	}
	else {
		LOG(Log, "[Connection: %s]Handshake response data send succeeded.", GetCurrentThreadId().c_str());
	}

	return sendResult != SOCKET_ERROR;
}

bool ProxyContext::SendLicenseResponse(ETravelResponse Response)
{
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

	int sendResult = send(Client, replyData.data(), static_cast<int>(replyData.size()), 0);
	if (sendResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %s]Send license response failed, code: %d", GetCurrentThreadId().c_str(), WSAGetLastError());
	}
	else {
		LOG(Log, "[Connection: %s]Send license response '%s' succeeded.", GetCurrentThreadId().c_str(), GetTravelResponseName(Response).c_str());
	}

	return sendResult != SOCKET_ERROR;
}

void ProxyContext::ProcessForwardData()
{
	switch (State)
	{
	case EConnectionState::Connected:
	{
		if (!TransportTraffic()) {
			State = EConnectionState::ReuqestClose;
			return;
		}

		break;
	}
	case EConnectionState::UDPAssociate:
	{
		if (!TransportUDPTraffic()) {
			State = EConnectionState::ReuqestClose;
			return;
		}
		break;
	}
	}
	
}

bool ProxyContext::TransportTraffic()
{
	FD_SET readSet;
	FD_ZERO(&readSet);
	FD_SET(Client, &readSet);
	FD_SET(Destination, &readSet);

	TIMEVAL timeout = { 1, 0 };

	int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
	if (selectResult < 0 || selectResult > 2) {
		LOG(Error, "[Connection: %s]Select result out of range %d, code: %d", GetCurrentThreadId().c_str(), selectResult, WSAGetLastError());
		return false;
	}


	if (FD_ISSET(Client, &readSet)) {
		if (!TransportTraffic(Client, Destination)) {
			return false;
		}
	}
	
	if (FD_ISSET(Destination, &readSet)) {
		if (!TransportTraffic(Destination, Client)) {
			return false;
		}
	}

	return true;
}

bool ProxyContext::TransportTraffic(SOCKET Source, SOCKET Target)
{
	int recvState(0), sendState(0), sentBytes(0);
	char buffer[TRAFFIC_BUFFER_SIZE];

	std::memset(buffer, 0, TRAFFIC_BUFFER_SIZE);
	recvState = recv(Source, buffer, TRAFFIC_BUFFER_SIZE, 0);
	if (recvState < 0) {
		LOG(Error, "[Connection: %s]Recv buffer error: %d , code: %d", GetCurrentThreadId().c_str(), recvState, WSAGetLastError());
		return false;
	}
	else if (recvState == 0) {
		return false;
	}
	else {
		sentBytes = 0;
		while (sentBytes < recvState)
		{
			sendState = send(Target, buffer + sentBytes, recvState - sentBytes, 0);
			if (sendState == SOCKET_ERROR) {
				if (WSAGetLastError() == 10035) {
					continue;
				}

				LOG(Error, "[Connection: %s]Send traffic error: %d, code: %d", GetCurrentThreadId().c_str(), sendState, WSAGetLastError());
				return false;
			}

			sentBytes += sendState;
		}
	}

	return true;
}

bool ProxyContext::TransportUDPTraffic()
{
	FD_SET readSet;
	FD_ZERO(&readSet);
	FD_SET(Client, &readSet);

	TIMEVAL timeout = { 1, 0 };

	int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
	if (selectResult < 0 || selectResult > 1) {
		LOG(Error, "[Connection: %s]Select result out of range %d, code: %d", GetCurrentThreadId().c_str(), selectResult, WSAGetLastError());
		return false;
	}

	int recvState(0), sendState(0), sentBytes(0);
	char buffer[TRAFFIC_BUFFER_SIZE];
	std::memset(buffer, 0, TRAFFIC_BUFFER_SIZE);

	if (FD_ISSET(Client, &readSet)) {
		recvState = recv(Client, buffer, TRAFFIC_BUFFER_SIZE, 0);
		if (recvState < 0) {
			LOG(Error, "[Connection: %s]Recv buffer error: %d , code: %d", GetCurrentThreadId().c_str(), recvState, WSAGetLastError());
			return false;
		}
		else if (recvState == 0) {
			return true;
		}
		else {
			while (sentBytes < recvState)
			{
				sendState = sendto(Destination, buffer + sentBytes, recvState - sentBytes, 0, (SOCKADDR*)&DestAddr, sizeof(DestAddr));
				if (sendState == SOCKET_ERROR) {
					if (WSAGetLastError() == 10035) {
						continue;
					}

					LOG(Error, "[Connection: %s]Send traffic error: %d, code: %d", GetCurrentThreadId().c_str(), sendState, WSAGetLastError());
					return false;
				}

				sentBytes += sendState;
			}
		}
	}

	std::memset(buffer,	0, TRAFFIC_BUFFER_SIZE);
	int addrLen = static_cast<int>(sizeof(DestAddr));
	recvState = recvfrom(Destination, buffer, TRAFFIC_BUFFER_SIZE, 0, (SOCKADDR*)&DestAddr, &addrLen);
	if (recvState < 0) {
		LOG(Error, "[Connection: %s]Recv buffer from dest error: %d , code: %d", GetCurrentThreadId().c_str(), recvState, WSAGetLastError());
		return false;
	}
	else if (recvState == 0) {
		return true;
	}
	else {
		UDPTravelReply reply = BuildUDPPacket(buffer, recvState);
		return SendUDPReply(reply);
	}
}

std::string ProxyContext::GetCurrentThreadId()
{
	std::stringstream stream;
	stream << std::this_thread::get_id();

	return stream.str();
}

std::string ProxyContext::GetTravelResponseName(ETravelResponse Response)
{
	switch (Response)
	{
	case ETravelResponse::Succeeded:
		return "Succeeded";
	case ETravelResponse::GeneralFailure:
		return "GeneralFailure";
	case ETravelResponse::RulesetNotAllowed:
		return "RulesetNotAllowed";
	case ETravelResponse::NetworkUnreachable:
		return "NetworkUnreachable";
	case ETravelResponse::HostUnreachable:
		return "HostUnreachable";
	case ETravelResponse::ConnectionRefused:
		return "ConnectionRefused";
	case ETravelResponse::TTL_Expired:
		return "TTL_Expired";
	case ETravelResponse::CmdNotSupported:
		return "CmdNotSupported";
	case ETravelResponse::AddrNotSupported:
		return "AddrNotSupported";
	case ETravelResponse::Unassigned:
		return "Unassigned";
	default:
		return "(null)";
	}
}

bool ProxyContext::ParsePayloadAddress()
{
	std::memset(&DestAddr, 0, sizeof(DestAddr));
	std::memcpy(&DestAddr.sin_port, LicensePayload.DestPort.data(), 2);
	switch (LicensePayload.AddressType)
	{
	case EAddressType::IPv4:
	{
		DestAddr.sin_family = AF_INET;

		std::memcpy(&DestAddr.sin_addr, LicensePayload.DestAddr.data(), 4);

		Destination = socket(AF_INET, SOCK_STREAM, 0);

		break;
	}
	case EAddressType::DomainName:
	{
		DestAddr.sin_family = AF_INET;

		ADDRINFO info, * result;
		std::memset(&info, 0, sizeof(ADDRINFO));
		info.ai_socktype = SOCK_STREAM;
		info.ai_family = AF_INET;

		int error = getaddrinfo(LicensePayload.DestAddr.data(), nullptr, &info, &result);
		if (error != 0) {
			LOG(Warning, "[Connection: %s]Convert hostname to ip address failed, err: %s.", GetCurrentThreadId().c_str(), gai_strerrorA(error));
			State = EConnectionState::LicenseError;
			SendLicenseResponse(ETravelResponse::HostUnreachable);
			return false;
		}

		DestAddr.sin_addr = ((SOCKADDR_IN*)(result->ai_addr))->sin_addr;

		freeaddrinfo(result);

		Destination = socket(AF_INET, SOCK_STREAM, 0);

		break;
	}
	case EAddressType::IPv6:
	{
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::AddrNotSupported);
		return false;
	}
	}

	if (Destination == INVALID_SOCKET) {
		LOG(Error, "[Connection: %s]Create a new socket to connect destination server failed, code: %d.", GetCurrentThreadId().c_str(), WSAGetLastError());
		SendLicenseResponse(ETravelResponse::GeneralFailure);
		return false;
	}

	return true;
}

UDPTravelReply ProxyContext::BuildUDPPacket(const char* Buffer, int Len)
{
	UDPTravelReply result;
	char reserved = 0x00;
	result.Reserved.push_back(reserved);
	result.Reserved.push_back(reserved);
	
	result.Fragment = 0x00;

	result.AddressType = LicensePayload.AddressType;

	result.BindAddress.resize(4);
	std::memcpy(result.BindAddress.data(), &DestAddr.sin_addr, 4);
	result.BindPort = LicensePayload.DestPort;

	result.Data.resize(Len);
	std::memcpy(result.Data.data(), Buffer, Len);

	return result;
}

bool ProxyContext::SendUDPReply(const UDPTravelReply& Reply)
{
	std::vector<char> replyBuffer;
	replyBuffer.insert(replyBuffer.end(), Reply.Reserved.begin(), Reply.Reserved.end());
	replyBuffer.push_back(Reply.Fragment);
	replyBuffer.push_back(static_cast<char>(Reply.AddressType));
	replyBuffer.insert(replyBuffer.end(), Reply.BindAddress.begin(), Reply.BindAddress.end());
	replyBuffer.insert(replyBuffer.end(), Reply.BindPort.begin(), Reply.BindPort.end());
	replyBuffer.insert(replyBuffer.end(), Reply.Data.begin(), Reply.Data.end());

	int sendState(0), sentBytes(0);
	int bufferSize = static_cast<int>(replyBuffer.size());
	while (sentBytes < bufferSize)
	{
		sendState = send(Client, replyBuffer.data() + sentBytes, bufferSize - sentBytes, 0);
		if (sendState == SOCKET_ERROR) {
			if (WSAGetLastError() == 10035) {
				continue;
			}

			LOG(Error, "[Connection: %s]Send traffic error: %d, code: %d", GetCurrentThreadId().c_str(), sendState, WSAGetLastError());
			return false;
		}

		sentBytes += sendState;
	}

	return true;
}
