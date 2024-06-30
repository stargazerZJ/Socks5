package Socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/puzpuzpuz/xsync/v3"
	"io"
	"net"
	"strconv"
	"time"
)

var ErrNotImplemented = errors.New("not implemented")

// Server is a Socks5 server.
type Server struct {
	Addr        string
	TCPListener *net.TCPListener
	Handler     Handler
	EnableUDP   bool
	EnableAuth  bool // Not implemented yet
	UDPListener *net.UDPConn
}

type Handler interface {
	HandleConnect(s *Server, request *Request, clientConn *net.TCPConn) error      // only return error if it's critical
	HandleUDPAssociate(s *Server, request *Request, clientConn *net.TCPConn) error // only return error if it's critical
	HandleUDP(s *Server, diagram *Datagram, clientAddr *net.UDPAddr) error         // only return error if it's critical
	Start() error                                                                  // Non-blocking
	Stop() error
}

type Request struct {
	Cmd     byte
	ATYP    byte
	DstAddr []byte // for domains, this doesn't include the domain length byte
	DstPort []byte
}

type Datagram struct {
	ATYP    byte
	DstAddr []byte // for domains, this doesn't include the domain length byte
	DstPort []byte
	Data    []byte
}

func (s *Server) ListenAndServe() error {
	err := s.Handler.Start()
	if err != nil {
		return err
	}

	if s.EnableUDP {
		udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
		if err != nil {
			s.Handler.Stop()
			return err
		}
		s.UDPListener, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			s.Handler.Stop()
			return err
		}
		go func() {
			buf := make([]byte, 65507)
			for {
				n, clientAddr, err := s.UDPListener.ReadFromUDP(buf)
				if err != nil {
					return
				}
				//log.Println("Got UDP datagram from", clientAddr.String())
				go func(buf []byte, n int, clientAddr *net.UDPAddr) {
					datagram, err := NewDatagram(buf[:n])
					if err != nil {
						return
					}
					err = s.Handler.HandleUDP(s, datagram, clientAddr)
					if err != nil {
						s.UDPListener.Close()
						return
					}
				}(buf[:n], n, clientAddr)
			}
		}()
	}

	if s.TCPListener != nil {
		s.UDPListener.Close()
		s.Handler.Stop()
		return fmt.Errorf("tcp listener already exists")
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		s.UDPListener.Close()
		s.Handler.Stop()
		return err
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		s.UDPListener.Close()
		s.Handler.Stop()
		return err
	}
	s.TCPListener = tcpListener

	for {
		conn, err := s.TCPListener.AcceptTCP()
		if err != nil {
			return nil
		}
		go func(conn *net.TCPConn) {
			defer conn.Close()
			request, err := s.handshake(conn)
			if err != nil || request == nil {
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
					s.sendErrorReply(conn, RepCommandNotSupported)
				}
			default:
				s.sendErrorReply(conn, RepCommandNotSupported)
			}
		}(conn)
	}
}

func (s *Server) Shutdown() error {
	if err := s.TCPListener.Close(); err != nil {
		return err
	}
	if s.EnableUDP {
		if err := s.UDPListener.Close(); err != nil {
			return err
		}
	}
	return s.Handler.Stop()
}

func NewServer(address string, enableAuth bool, username, password string, enableUDP bool, handler Handler) (*Server, error) {
	if enableAuth {
		return nil, fmt.Errorf("authentication is not implemented")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("invalid address: %s", address)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid port: %s", port)
	}

	return &Server{
		Addr:       address,
		EnableUDP:  enableUDP,
		EnableAuth: enableAuth,
		Handler:    handler,
	}, nil
}

func (s *Server) handshake(conn *net.TCPConn) (*Request, error) {
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

	request := &Request{
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

func NewDatagram(buf []byte) (*Datagram, error) {
	if buf[0] != 0 || buf[1] != 0 {
		return nil, fmt.Errorf("RSV should be 0")
	}

	frag := buf[2]
	if frag != 0 {
		return nil, fmt.Errorf("fragmentation is not supported")
	}
	atyp := buf[3]
	addrLen := 0
	switch atyp {
	case ATYPIPv4:
		addrLen = 4
	case ATYPDomain:
		addrLen = int(buf[4])
		if addrLen == 0 {
			return nil, fmt.Errorf("address length is 0")
		}
	case ATYPIPv6:
		addrLen = 16
	default:
		return nil, fmt.Errorf("address type not supported")
	}
	addr := buf[4 : 4+addrLen]
	port := buf[4+addrLen : 4+addrLen+2]
	data := buf[4+addrLen+2:]
	if atyp == ATYPDomain {
		addr = addr[1:]
	}
	return &Datagram{
		ATYP:    atyp,
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}, nil
}

func contains(slice []byte, item byte) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// return address:port
func (r *Request) Address() (string, error) {
	port := binary.BigEndian.Uint16(r.DstPort)
	var address string
	switch r.ATYP {
	case ATYPIPv4:
		address = fmt.Sprintf("%s:%d", net.IP(r.DstAddr).String(), port)
	case ATYPIPv6:
		address = fmt.Sprintf("[%s]:%d", net.IP(r.DstAddr).String(), port)
	case ATYPDomain:
		address = fmt.Sprintf("%s:%d", string(r.DstAddr), port)
	default:
		return "", fmt.Errorf("unsupported address type: %d", r.ATYP)
	}
	if address == "" {
		return "", fmt.Errorf("failed to format address")
	}
	return address, nil
}

func (d *Datagram) Address() (string, error) {
	port := binary.BigEndian.Uint16(d.DstPort)
	var address string
	switch d.ATYP {
	case ATYPIPv4:
		address = fmt.Sprintf("%s:%d", net.IP(d.DstAddr).String(), port)
	case ATYPIPv6:
		address = fmt.Sprintf("[%s]:%d", net.IP(d.DstAddr).String(), port)
	case ATYPDomain:
		address = fmt.Sprintf("%s:%d", string(d.DstAddr), port)
	default:
		return "", fmt.Errorf("unsupported address type: %d", d.ATYP)
	}
	if address == "" {
		return "", fmt.Errorf("failed to format address")
	}
	return address, nil
}

type DefaultHandler struct {
	associations *xsync.MapOf[string, association]
	lastReqTime  *xsync.MapOf[string, time.Time]
	ticker       *time.Ticker // used by the cleaner goroutine
}

type association struct {
	remoteConn      *net.UDPConn
	associationConn *net.TCPConn // when this is closed by the timer or the client, the association is deleted by HandleUDPAssociate
}

func (h *DefaultHandler) HandleConnect(s *Server, request *Request, clientConn *net.TCPConn) error {
	dstAddr, err := request.Address()
	if err != nil {
		s.sendErrorReply(clientConn, RepAddressNotSupported)
		return nil
	}

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

func (h *DefaultHandler) HandleUDPAssociate(s *Server, request *Request, clientConn *net.TCPConn) error {
	// Acquire the address that the client is going to use to send UDP datagrams
	clientAddrStr, err := request.Address()
	if err != nil {
		s.sendErrorReply(clientConn, RepAddressNotSupported)
		return nil
	}
	if bytes.Compare(request.DstPort, []byte{0, 0}) == 0 {
		// RFC: If the client is not in possesion of the information at the time of the UDP ASSOCIATE, the client MUST use a port number and address of all zeros.
		clientAddrStr = clientConn.RemoteAddr().String()
	}
	clientAddr, err := net.ResolveUDPAddr("udp", clientAddrStr)
	if err != nil {
		s.sendErrorReply(clientConn, RepAddressNotSupported)
		return nil
	}
	//log.Println("The client wants to start a UDP talk using", clientAddr.String())

	// Resolve the UDP address with port 0 to let the system assign an available port
	udpAddr, err := net.ResolveUDPAddr("udp", "[::]:0")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Create a UDP connection that will be used to send and receive UDP datagrams to the destination
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP address: %w", err)
	}
	//log.Println("UDP ASSOCIATE", udpConn.LocalAddr().String())
	defer udpConn.Close()

	// send success reply to the user. use clientConn.LocalAddr() as the address to send the success to.
	bndAddrTCP := clientConn.LocalAddr().(*net.TCPAddr)
	bndAddrUDP := &net.UDPAddr{
		IP:   bndAddrTCP.IP,
		Port: bndAddrTCP.Port,
	}

	bndAddrBytes := bndAddrUDP.IP.To4()
	atyp := ATYPIPv4
	if bndAddrBytes == nil {
		bndAddrBytes = bndAddrUDP.IP.To16()
		atyp = ATYPIPv6
	}
	bndPort := make([]byte, 2)
	binary.BigEndian.PutUint16(bndPort, uint16(bndAddrUDP.Port))
	//log.Println("Reply address", bndAddrUDP.String())

	reply := []byte{Socks5Ver, RepSuccess, 0x00, atyp}
	reply = append(reply, bndAddrBytes...)
	reply = append(reply, bndPort...)

	_, err = clientConn.Write(reply)
	if err != nil {
		return nil
	}

	// Add the association to the map
	h.associations.Store(clientAddrStr, association{
		remoteConn:      udpConn,
		associationConn: clientConn,
	})

	// Start a goroutine to copy data from udpConn to clientConn, with socks5 datagram header. Full cone NAT
	go func() {
		buf := make([]byte, 65507)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			//log.Println("the Remote UDP conn got a datagram from", addr.String(), "length", n, "bytes")
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			// Create a SOCKS5 UDP datagram header
			header := make([]byte, 10)
			header[0] = 0x00 // Reserved
			header[1] = 0x00 // Reserved
			header[2] = 0x00 // Fragment number
			header = header[:4]

			// Address type and address
			ip := addr.IP.To4()
			if ip != nil {
				header[3] = ATYPIPv4
				header = append(header, ip...)
			} else {
				header[3] = ATYPIPv6
				header = append(header, addr.IP...)
			}

			// Port
			port := make([]byte, 2)
			binary.BigEndian.PutUint16(port, uint16(addr.Port))
			header = append(header, port...)

			// Send the datagram with the header to the client
			s.UDPListener.WriteToUDP(append(header, buf[:n]...), clientAddr)

			// refresh the last request time
			h.lastReqTime.Store(clientAddrStr, time.Now())
		}
	}()

	// wait for the client to close the TCP connection and close closeChan
	io.Copy(io.Discard, clientConn)
	udpConn.Close()
	h.associations.Delete(clientAddrStr)
	h.lastReqTime.Delete(clientAddrStr)

	return nil
}

func (h *DefaultHandler) HandleUDP(s *Server, diagram *Datagram, clientAddr *net.UDPAddr) error {
	dstAddrStr, err := diagram.Address()
	if err != nil {
		return nil
	}

	clientAddrStr := clientAddr.String()

	association, ok := h.associations.Load(clientAddrStr)
	if !ok {
		return nil
	}

	dstAddr, err := net.ResolveUDPAddr("udp", dstAddrStr)
	if err != nil {
		return nil
	}

	association.remoteConn.WriteToUDP(diagram.Data, dstAddr)

	// refresh the last request time
	h.lastReqTime.Store(clientAddrStr, time.Now())
	return nil
}

func (h *DefaultHandler) Start() error {
	// start the cleanup goroutine that checks every 300 sec and close connections older than 60 sec
	h.ticker = time.NewTicker(300 * time.Second)
	go func() {
		for range h.ticker.C {
			now := time.Now()
			h.lastReqTime.Range(func(key string, timestamp time.Time) bool {
				if now.Sub(timestamp) > 60*time.Second {
					association, ok := h.associations.Load(key)
					if ok {
						association.associationConn.Close()
					}
				}
				return true
			})
		}
	}()
	return nil
}

func (h *DefaultHandler) Stop() error {
	h.ticker.Stop()
	return nil
}

// NewDefaultHandler creates a new DefaultHandler
func NewDefaultHandler() *DefaultHandler {
	return &DefaultHandler{
		associations: xsync.NewMapOf[string, association](),
		lastReqTime:  xsync.NewMapOf[string, time.Time](),
	}
}
