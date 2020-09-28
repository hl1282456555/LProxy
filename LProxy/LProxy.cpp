// LProxy.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "ProxyServer.h"

int main()
{
	std::shared_ptr<ProxyServer> server = ProxyServer::Get();

	server->InitSocket();
	server->Run();

	return 0;
}
