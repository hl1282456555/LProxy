#include "ClientSocket.h"

ClientSocket::ClientSocket()
	: Addr()
	, SockHandle(INVALID_SOCKET)
{

}

ClientSocket::ClientSocket(SOCKADDR_IN InAddr, SOCKET InHandle)
	: Addr(InAddr)
	, SockHandle(InHandle)
{

}

ClientSocket::~ClientSocket()
{
	if (SockHandle == INVALID_SOCKET) {
		return;
	}

	closesocket(SockHandle);
}

void ClientSocket::InitConnection()
{

}
