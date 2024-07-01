package Socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/puzpuzpuz/xsync/v3"
	"io"
	"log"
	"net"
	"time"
)

type LooseUDPHandler struct {
	associations *xsync.MapOf[string, *net.UDPConn]
	lastReqTime  *xsync.MapOf[string, time.Time]
	ticker       *time.Ticker // used by the cleaner goroutine
}

func (h *LooseUDPHandler) HandleConnect(s *Server, request *Request, clientConn *net.TCPConn) error {
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

func (h *LooseUDPHandler) HandleUDPAssociate(s *Server, request *Request, clientConn *net.TCPConn) error {
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

	reply := []byte{Socks5Ver, RepSuccess, 0x00, atyp}
	reply = append(reply, bndAddrBytes...)
	reply = append(reply, bndPort...)

	_, err := clientConn.Write(reply)
	if err != nil {
		return nil
	}
	return nil
}

func (h *LooseUDPHandler) HandleUDP(s *Server, datagram *Datagram, clientAddr *net.UDPAddr) error {
	dstAddrStr, err := datagram.Address()
	if err != nil {
		return nil
	}

	clientAddrStr := clientAddr.String()

	log.Println("Got UDP datagram from", clientAddr.String(), "to", dstAddrStr, "length", len(datagram.Data))

	association, ok := h.associations.Load(clientAddrStr)
	if !ok {
		log.Println("No association found for", clientAddrStr, "creating one")
		association, err = h.createAssociation(s.UDPListener, clientAddr)
		if err != nil {
			log.Println("Failed to create association for", clientAddrStr, err)
			return nil
		}
	}

	dstAddr, err := net.ResolveUDPAddr("udp", dstAddrStr)
	if err != nil {
		log.Println("Failed to resolve UDP address", dstAddrStr, err)
		return nil
	}

	_, err = association.WriteToUDP(datagram.Data, dstAddr)
	if err != nil {
		log.Println("Failed to write to the association", err)
		return nil
	}

	// refresh the last request time
	h.lastReqTime.Store(clientAddrStr, time.Now())
	return nil
}

func (h *LooseUDPHandler) createAssociation(UDPListener *net.UDPConn, clientAddr *net.UDPAddr) (*net.UDPConn, error) {
	// Resolve the UDP address with port 0 to let the system assign an available port
	udpAddr, err := net.ResolveUDPAddr("udp", "[::]:0")
	if err != nil {
		return nil, fmt.Errorf("failed to assign a UDP port: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	clientAddrStr := clientAddr.String()
	h.associations.Store(clientAddrStr, udpConn)
	h.lastReqTime.Store(clientAddrStr, time.Now())

	// Start a goroutine to copy data from udpConn to clientConn, with socks5 datagram header. Full cone NAT
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			//log.Println("the Remote UDP conn got a datagram from", addr.String(), "length", n, "bytes")
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
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

			log.Println("the Remote UDP conn got a datagram from", addr.String(), "length", n, "bytes", "header", header, "data", buf[:n])
			log.Println("Sending to the client", clientAddr.String())

			// Send the datagram with the header to the client
			_, err = UDPListener.WriteToUDP(append(header, buf[:n]...), clientAddr)
			if err != nil {
				return
			}

			// refresh the last request time
			h.lastReqTime.Store(clientAddrStr, time.Now())
		}
	}()

	return udpConn, nil
}

func (h *LooseUDPHandler) Start() error {
	// start the cleanup goroutine that checks every 300 sec and close connections older than 60 sec
	h.ticker = time.NewTicker(300 * time.Second)
	go func() {
		for range h.ticker.C {
			now := time.Now()
			h.lastReqTime.Range(func(key string, timestamp time.Time) bool {
				if now.Sub(timestamp) > 60*time.Second {
					association, ok := h.associations.Load(key)
					if ok {
						association.Close()
						h.associations.Delete(key)
					}
					h.lastReqTime.Delete(key)
				}
				return true
			})
		}
	}()
	return nil
}

func (h *LooseUDPHandler) Stop() error {
	h.ticker.Stop()
	return nil
}

func NewLooseUDPHandler() *LooseUDPHandler {
	return &LooseUDPHandler{
		associations: xsync.NewMapOf[string, *net.UDPConn](),
		lastReqTime:  xsync.NewMapOf[string, time.Time](),
	}
}
