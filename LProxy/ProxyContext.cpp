#include "ProxyContext.h"
#include "EasyLog.h"
#include "BufferReader.h"
#include "ProxyServer.h"

ProxyContext::ProxyContext(SOCKET InClient, EConnectionState InState /*= EConnectionState::WaitHandshake*/)
	: State(InState)
	, Client(InClient)
{
}

ProxyContext::~ProxyContext()
{
	if (Client != INVALID_SOCKET) {
		LOG(Log, "[Connection: %d]Disconnecting.", Client);
		closesocket(Client);
		Client = INVALID_SOCKET;
	}

	if (Destination != INVALID_SOCKET) {
		LOG(Log, "[Connection: %d]Disconnecting.", Destination);
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
	LOG(Log, "[Connection: %d]Processing handshake.", Client);

	char handshakeData[TRAFFIC_BUFFER_SIZE];
	int recvResult = recv(Client, handshakeData, TRAFFIC_BUFFER_SIZE, 0);
	if (recvResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %d]Recv handshake occured some errors, code: %d", WSAGetLastError());
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
		LOG(Warning, "[Connection: %d]Wrong protocol version.", Client);
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	if (packet.MethodNum < 1) {
		LOG(Warning, "[Connection: %d]Wrong method length.", Client);
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
		LOG(Warning, "[Connection: %d]Only support non-auth protocol now.", Client);
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	State = EConnectionState::WaitLicense;
	SendHandshakeResponse(EConnectionProtocol::Non_auth);
}

void ProxyContext::ProcessWaitLicense()
{
	LOG(Log, "[Connection: %d]Processing wait license.", Client);

	char licenseData[TRAFFIC_BUFFER_SIZE];
	int recvResult = recv(Client, licenseData, TRAFFIC_BUFFER_SIZE, 0);
	if (recvResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %d]Recv license occured some errors, code: %d", WSAGetLastError());
		State = EConnectionState::HandshakeError;
		SendHandshakeResponse(EConnectionProtocol::Error);
		return;
	}

	BufferReader reader(licenseData, TRAFFIC_BUFFER_SIZE);

	reader.Serialize(&LicensePayload.Version, 1);

	if (LicensePayload.Version != ESocksVersion::Socks5) {
		LOG(Warning, "[Connection: %d]Wrong protocol version.", Client);
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::GeneralFailure);
		return;
	}

	reader.Serialize(&LicensePayload.Cmd, 1);
	reader.Serialize(&LicensePayload.Reserved, 1);

	if (LicensePayload.Reserved != 0x00) {
		LOG(Warning, "[Connection: %d]Wrong reserved field value.", Client);
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
		LOG(Warning, "[Connection: %d]Wrong address type.", Client);
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
		LOG(Warning, "[Connection: %d]Not supported command.", Client);
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::CmdNotSupported);
		return;
	}
}

bool ProxyContext::ProcessConnectCmd()
{
	SOCKADDR_IN destAddr;
	std::memset(&destAddr, 0, sizeof(destAddr));
	std::memcpy(&destAddr.sin_port, LicensePayload.DestPort.data(), 2);
	switch (LicensePayload.AddressType)
	{
	case EAddressType::IPv4:
	{
		destAddr.sin_family = AF_INET;

		std::memcpy(&destAddr.sin_addr, LicensePayload.DestAddr.data(), 4);

		Destination = socket(AF_INET, SOCK_STREAM, 0);

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
			LOG(Warning, "[Connection: %d]Convert hostname to ip address failed, err: %s.", Client, gai_strerrorA(error));
			State = EConnectionState::LicenseError;
			SendLicenseResponse(ETravelResponse::HostUnreachable);
			return false;
		}

		destAddr.sin_addr = ((SOCKADDR_IN*)(result->ai_addr))->sin_addr;

		freeaddrinfo(result);

		Destination = socket(AF_INET, SOCK_STREAM, 0);

		break;
	}
	case EAddressType::IPv6:
	{
		State = EConnectionState::LicenseError;
		SendLicenseResponse(ETravelResponse::AddrNotSupported);
		break;
	}
	}

	if (Destination == INVALID_SOCKET) {
		LOG(Error, "[Connection: %d]Create a new socket to connect destination server failed, code: %d.", Client, WSAGetLastError());
		SendLicenseResponse(ETravelResponse::GeneralFailure);
		return false;
	}

	int connectResult = connect(Destination, (SOCKADDR*)&destAddr, sizeof(destAddr));
	if (connectResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %d]Connect to destination server failure, code: %d.", Client, WSAGetLastError());
		SendLicenseResponse(ETravelResponse::NetworkUnreachable);
		return false;
	}

	LOG(Log, "[Connection: %d]Connect to destination server succeeded.", Client);
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

	

	int sendResult = send(Client, responseData.data(), static_cast<int>(responseData.size()), 0);
	if (sendResult == SOCKET_ERROR) {
		LOG(Error, "[Connection: %d]Send handshake response failed, code: %d", Client, WSAGetLastError());
	}
	else {
		LOG(Log, "[Connection: %d]Handshake response data send succeeded.", Client);
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
		LOG(Error, "[Connection: %d]Send license response failed, code: %d", Client, WSAGetLastError());
	}
	else {
		LOG(Log, "[Connection: %d]Send license response succeeded.");
	}

	return sendResult != SOCKET_ERROR;
}

void ProxyContext::ProcessForwardData()
{
	switch (State)
	{
	case EConnectionState::Connected:
	{
		if (!TransportTraffic(Client, Destination)) {
			LOG(Error, "[Connection: %d]Transport traffic to destination failed, code: %d", Client, WSAGetLastError());
			State = EConnectionState::ReuqestClose;
			return;
		}

		if (!TransportTraffic(Destination, Client)) {
			LOG(Error, "[Connection: %d]Transport traffic to client failed, code: %d", Client, WSAGetLastError());
			State = EConnectionState::ReuqestClose;
			return;
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

int ProxyContext::RecvTrafficFromSocket(SOCKET InSocket, std::vector<char>& TrafficData)
{
	TrafficData.resize(0);

	int recvResult = 0;
	while(true) {
		char tempData[TRAFFIC_BUFFER_SIZE] = { 0 };
		recvResult = recv(InSocket, tempData, TRAFFIC_BUFFER_SIZE, 0);
		if (recvResult <= 0) {
			break;
		}

		TrafficData.insert(TrafficData.end(), tempData, tempData + recvResult + 1);
	}

	return recvResult == SOCKET_ERROR ? recvResult : TrafficData.size();
}

int ProxyContext::SendTrafficToSocket(SOCKET InSocket, const std::vector<char>& TrafficData)
{
	if (TrafficData.empty()) {
		return 0;
	}
	int sendResult(0), sentBytes(0);
	int totalBytes = TrafficData.size();

	do {
		sendResult = send(InSocket, TrafficData.data() + sentBytes, totalBytes - sentBytes, 0);
		if (sendResult == SOCKET_ERROR) {
			return sendResult;
		}

		sentBytes += sendResult;
	} while (sentBytes < totalBytes);

	return sentBytes;
}

bool ProxyContext::TransportTraffic(SOCKET Source, SOCKET Target)
{
	int recvState(0);
	std::vector<char> trafficData;
	recvState = RecvTrafficFromSocket(Source, trafficData);
	if (recvState == SOCKET_ERROR) {
		return false;
	}

	if (recvState == 0) {
		return true;
	}

	return SendTrafficToSocket(Target, trafficData) > 0;
}
