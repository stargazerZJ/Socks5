package Socks5

const (
	Socks5Ver byte = 0x05

	MethodNoAuth       byte = 0x00 // NO AUTHENTICATION REQUIRED
	MethodGSSAPI       byte = 0x01 // GSSAPI
	MethodUserPass     byte = 0x02 // USERNAME/PASSWORD
	MethodNoAcceptable byte = 0xFF // No acceptable methods

	CmdConnect      byte = 0x01 // CONNECT
	CmdBind         byte = 0x02 // BIND
	CmdUDPAssociate byte = 0x03 // UDP ASSOCIATE

	ATYPIPv4   byte = 0x01 // IPv4 address
	ATYPDomain byte = 0x03 // DOMAINNAME
	ATYPIPv6   byte = 0x04 // IPv6 address

	RepSuccess             byte = 0x00 // succeeded
	RepServerFailure       byte = 0x01 // general SOCKS server failure
	RepNotAllowed          byte = 0x02 // connection not allowed by ruleset
	RepNetworkUnreachable  byte = 0x03 // Network unreachable
	RepHostUnreachable     byte = 0x04 // Host unreachable
	RepConnectionRefused   byte = 0x05 // Connection refused
	RepTTLExpired          byte = 0x06 // TTL expired
	RepCommandNotSupported byte = 0x07 // Command not supported
	RepAddressNotSupported byte = 0x08 // Address type not supported

)
