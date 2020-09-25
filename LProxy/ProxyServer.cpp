#include "ProxyServer.h"
#include "EasyLog.h"

ProxyServer::ProxyServer()
{

}

ProxyServer::~ProxyServer()
{

}

bool ProxyServer::Listen()
{
	try {
		if (!IsValid()) {
			throw "The socket not initialized.";
		}

		SockState = ESocketState::Connecting;
	}
	catch (const std::exception& Err) {
		LOG(Log, "Startup listen server failed, err: %s", Err.what());
		return false;
	}
}
