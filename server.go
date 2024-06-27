package Socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/txthinking/runnergroup"
	"io"
	"net"
	"strconv"
)

var ErrNotImplemented = errors.New("not implemented")

// Server is a Socks5 server.
type Server struct {
	Addr        string
	TCPListener *net.TCPListener
	Handler     Handler
	EnableUDP   bool // Not implemented yet
	EnableAuth  bool // Not implemented yet
	RunnerGroup *runnergroup.RunnerGroup
}

type Handler interface {
	HandleConnect(s *Server, request *Socks5Request, clientConn *net.TCPConn) error // only return error if it's critical
	HandleUDPAssociate(s *Server, request *Socks5Request, clientConn *net.TCPConn) error // only return error if it's critical
	//HandleUDP(s *Server, diagram UDPDiagram, clientConn *net.UDPConn) error // Not implemented yet
}

type Socks5Request struct {
	Cmd     byte
	ATYP    byte
	DstAddr []byte // for domains, this doesn't include the domain length byte
	DstPort []byte
}

func (s *Server) ListenAndServe() error {
	if s.TCPListener == nil {
		tcpAddr, err := net.ResolveTCPAddr("tcp", s.Addr)
		if err != nil {
			return err
		}
		tcpListener, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return err
		}
		s.TCPListener = tcpListener
	} else {
		return fmt.Errorf("tcp listener already exists")
	}

	for {
		conn, err := s.TCPListener.AcceptTCP()
		if err != nil {
			return err
		}
		go func(conn *net.TCPConn) {
			request, err := s.handshake(conn)
			if err != nil || request == nil {
				conn.Close()
				return
			}
			switch request.Cmd {
			case CmdConnect:
				err = s.Handler.HandleConnect(s, request, conn)
				if err != nil {
					s.Shutdown()
				}
			case CmdUDPAssociate:
				if s.EnableUDP {
					err = s.Handler.HandleUDPAssociate(s, request, conn)
					if err != nil {
						s.Shutdown()
					}
				} else {
					conn.Close()
				}
			default:
				s.sendErrorReply(conn, RepCommandNotSupported)
				conn.Close()
			}
		}(conn)
	}
}

func (s *Server) Shutdown() error {
	if err := s.TCPListener.Close(); err != nil {
		return err
	}
	return nil
}

func NewServer(address string, enableAuth bool, username, password string, enableUDP bool, handler Handler) (*Server, error) {
	if enableAuth {
		return nil, fmt.Errorf("authentication is not implemented")
	}
	if enableUDP {
		return nil, fmt.Errorf("UDP is not implemented")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("invalid address: %s", address)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid port: %s", port)
	}

	return &Server{
		Addr:        address,
		EnableUDP:   enableUDP,
		EnableAuth:  enableAuth,
		Handler:     handler,
		RunnerGroup: runnergroup.New(),
	}, nil
}

func (s *Server) handshake(conn *net.TCPConn) (*Socks5Request, error) {
	// Read the first 2 bytes to get the version and number of methods
	header := make([]byte, 2)
	_, err := conn.Read(header)
	if err != nil {
		return nil, fmt.Errorf("failed to read from connection: %w", err)
	}

	if header[0] != Socks5Ver {
		s.sendErrorReply(conn, RepServerFailure)
		return nil, nil
	}
	nMethods := int(header[1])
	if nMethods == 0 {
		s.sendErrorReply(conn, RepServerFailure)
		return nil, nil
	}

	// Read the methods
	methods := make([]byte, nMethods)
	_, err = conn.Read(methods)
	if err != nil {
		return nil, fmt.Errorf("failed to read methods from connection: %w", err)
	}

	// Check if the methods are correct
	if s.EnableAuth {
		return nil, ErrNotImplemented
	} else {
		if !contains(methods, MethodNoAuth) {
			conn.Write([]byte{Socks5Ver, MethodNoAcceptable})
			return nil, nil
		}

		_, err = conn.Write([]byte{Socks5Ver, MethodNoAuth})
		if err != nil {
			s.sendErrorReply(conn, RepServerFailure)
			return nil, nil
		}
	}

	// Read the SOCKS5 request
	requestHeader := make([]byte, 4)
	_, err = conn.Read(requestHeader)
	if err != nil {
		s.sendErrorReply(conn, RepServerFailure)
		return nil, nil
	}

	// Check if the version is correct
	if requestHeader[0] != Socks5Ver {
		s.sendErrorReply(conn, RepServerFailure)
		return nil, nil
	}

	// RSV should be 0
	if requestHeader[2] != 0 {
		s.sendErrorReply(conn, RepCommandNotSupported)
		return nil, nil
	}

	// Read the address
	var addrLen int
	switch requestHeader[3] {
	case ATYPIPv4:
		addrLen = 4
	case ATYPDomain:
		_, err = conn.Read(requestHeader[:1])
		if err != nil {
			s.sendErrorReply(conn, RepServerFailure)
			return nil, nil
		}
		addrLen = int(requestHeader[0])
	case ATYPIPv6:
		addrLen = 16
	default:
		s.sendErrorReply(conn, RepAddressNotSupported)
		return nil, nil
	}

	addr := make([]byte, addrLen+2) // address + 2 bytes for port
	_, err = conn.Read(addr)
	if err != nil {
		s.sendErrorReply(conn, RepServerFailure)
		return nil, nil
	}

	request := &Socks5Request{
		Cmd:     requestHeader[1],
		ATYP:    requestHeader[3],
		DstAddr: addr[:addrLen],
		DstPort: addr[addrLen:],
	}

	return request, nil
}

func (s *Server) sendErrorReply(conn *net.TCPConn, rep byte) {
	conn.Write([]byte{Socks5Ver, rep, 0x00, ATYPIPv4, 0, 0, 0, 0, 0, 0})
}

func contains(slice []byte, item byte) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

type DefaultHandler struct{}

func (h *DefaultHandler) HandleConnect(s *Server, request *Socks5Request, clientConn *net.TCPConn) error {
	var dstAddr string

	switch request.ATYP {
	case ATYPIPv4:
		dstAddr = net.IP(request.DstAddr).String()
	case ATYPIPv6:
		dstAddr = fmt.Sprintf("[%s]", net.IP(request.DstAddr).String())
	case ATYPDomain:
		dstAddr = string(request.DstAddr)
	default:
		s.sendErrorReply(clientConn, RepAddressNotSupported)
		return fmt.Errorf("address type not supported")
	}

	dstAddr = fmt.Sprintf("%s:%d", dstAddr, binary.BigEndian.Uint16(request.DstPort))

	// Establish a connection to the destination
	dstConn, err := net.Dial("tcp", dstAddr)
	if err != nil {
		s.sendErrorReply(clientConn, RepHostUnreachable)
		return nil
	}
	defer dstConn.Close()
	defer clientConn.Close()

	// Send a success reply to the client
	_, err = clientConn.Write([]byte{Socks5Ver, RepSuccess, 0x00, request.ATYP})
	if err != nil {
		return nil
	}
	if request.ATYP == ATYPDomain {
		_, err = clientConn.Write([]byte{byte(len(request.DstAddr))})
		if err != nil {
			return nil
		}
	}
	_, err = clientConn.Write(request.DstAddr)
	if err != nil {
		return nil
	}
	_, err = clientConn.Write(request.DstPort)
	if err != nil {
		return nil
	}

	// Start relaying data between client and destination
	go func() {
		_, _ = io.Copy(dstConn, clientConn)
		dstConn.Close()
        clientConn.Close()
	}()
	_, err = io.Copy(clientConn, dstConn)
	if err != nil && err != io.EOF {
		return nil
	}

	return nil
}

func (h *DefaultHandler) HandleUDPAssociate(s *Server, request *Socks5Request, clientConn *net.TCPConn) error {
	return ErrNotImplemented
}
