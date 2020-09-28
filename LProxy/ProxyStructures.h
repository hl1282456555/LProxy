#ifndef PROXY_STRUCTURES_H
#define PROXY_STRUCTURES_H

#include <vector>

enum class EConnectionState
{
	None = 0,
	Handshark,
	CheckLicense,
	Connected,
	RequestClose,
};

enum class EConnectionProtocol
{
	Non_auth	= 0x00,
	GSSAPI		= 0x01,
	Password	= 0x02,
	IANA		= 0x03,
	Custom_B	= 0x80,
	Custom_E	= 0xfe,
	Error		= 0xff,
};

enum class ESocksVersion
{
	None	= 0x00,
	Socks4	= 0x04,
	Socks5	= 0x05,
};

struct HandshakePacket
{
	// Protocol version
	ESocksVersion Version{ESocksVersion::None};

	// Number of method
	int MethodNum{0};

	// Methods
	std::vector<EConnectionProtocol> MethodList;
};

struct HandshakeResponse
{
	// Protocol version
	ESocksVersion Version{ESocksVersion::None};

	// Choiced method
	EConnectionProtocol Method{EConnectionProtocol::Non_auth};
};

enum class ECommandType
{
	Connect = 0x01,
	Bind	= 0x02,
	UDP		= 0x03,
};

enum class EAddressType
{
	IPv4		= 0x01,
	DomainName	= 0x03,
	IPv6		= 0x04,
};

struct TravelPayload
{
	// Protocol version
	ESocksVersion Version{ESocksVersion::None};

	/**
	* Connect command
	* @see ECommandType
	*/
	ECommandType Cmd{ECommandType::Connect};

	/**
	* Reserved field, not used now.
	* 0x00	default value
	*/
	char Reserved;

	/**
	* target address type
	* @See EAddressType
	*/
	EAddressType AddressType{EAddressType::IPv4};

	/**
	* Desired destination address
	* [IPv4]		A version-4 IP address, with a length of 4 octets
	* [DomainName]	Fully-qualified domain name, the first octet of 
					the address field contains the number of octets of name that follow,
					there is no terminating NUL octet.
	* [IPv6]		A version-6 IP address, with a length of 16 octets.
	*/
	std::vector<char> DestAddr;

	/**
	* Desired destination port in network octet order
	*/
	std::vector<char> DestPort;
};

enum class ETravelResponse
{
	Succeeded			= 0x00,
	GeneralFailure		= 0x01,
	RulesetNotAllowed	= 0x02,
	NetworkUnreachable	= 0x03,
	HostUnreachable		= 0x04,
	ConnectionRefused	= 0x05,
	TTL_Expired			= 0x06,
	CmdNotSupported		= 0x07,
	AddrNotSupported	= 0x08,
	Unassigned			= 0x09,
};

struct TravelReply
{
	// Protocol version
	ESocksVersion Version{ESocksVersion::None};

	/**
	* Reply field
	* @see ETravelResponse
	*/
	ETravelResponse Reply{ETravelResponse::Succeeded};

	/**
	* Reserved field
	* 0x00	default value
	*/
	char Reserved;

	/**
	* Address type of following address
	* @see EAddressType
	*/
	EAddressType AddressType{EAddressType::IPv4};

	/**
	* Server bound address
	* [IPv4]		A version-4 IP address, with a length of 4 octets
	* [DomainName]	Fully-qualified domain name, the first octet of
					the address field contains the number of octets of name that follow,
					there is no terminating NUL octet.
	* [IPv6]		A version-6 IP address, with a length of 16 octets.
	*/
	std::vector<char> BindAddress;

	/**
	* Server bound port in network octet order
	*/
	std::vector<char> BindPort;
};

#endif // !PROXY_STRUCTURES_H
