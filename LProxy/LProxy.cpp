// LProxy.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "ProxyServer.h"
#include "EasyLog.h"

int main()
{
	std::shared_ptr<ProxyServer> server = ProxyServer::Get();

	if (!server->InitServer()) {
		LOG(Error, "[Main]Init the proxy server failed.");
		return -1;
	}

	return 0;
}
