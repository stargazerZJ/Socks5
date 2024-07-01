package Socks5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type TCPOnlyHandler struct{}

func (h *TCPOnlyHandler) HandleConnect(s *Server, request *Request, clientConn *net.TCPConn) error {
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

	// Start relaying data between client and destination with logging
	h.relayAndSniff(clientConn, dstConn)

	return nil
}

func (h *TCPOnlyHandler) relay(clientConn *net.TCPConn, dstConn net.Conn) {
	go func() {
		_, _ = io.Copy(dstConn, clientConn)
		dstConn.Close()
		clientConn.Close()
	}()
	_, _ = io.Copy(clientConn, dstConn)
	clientConn.Close()
	dstConn.Close()
}

func (h *TCPOnlyHandler) relayAndLogHexdump(clientConn *net.TCPConn, dstConn net.Conn) {
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				log.Printf("Client (%s) to Server (%s), len (%d):\n%s", clientConn.RemoteAddr(), dstConn.RemoteAddr(), n, hex.Dump(buf[:n]))
				_, _ = dstConn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		dstConn.Close()
		clientConn.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, err := dstConn.Read(buf)
		if n > 0 {
			log.Printf("Server (%s) to Client (%s), len (%d):\n%s", dstConn.RemoteAddr(), clientConn.RemoteAddr(), n, hex.Dump(buf[:n]))
			_, _ = clientConn.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			break
		}
	}
	return
}

func (h *TCPOnlyHandler) relayAndSniff(clientConn *net.TCPConn, dstConn net.Conn) {
	go func() {
		buf := make([]byte, 4096)
		n, err := clientConn.Read(buf)
		if n > 0 {
			// Sniff HTTP host
			log.Printf("Client (%s) to Server (%s), len : %d", clientConn.RemoteAddr(), dstConn.RemoteAddr(), n)
			host := SniffHTTPHost(buf[:n])
			if host != "" {
				log.Printf("Sniffed HTTP Host: %s", host)
			}
			// Sniff TLS SNI
			sni := SniffTLSSNI(buf[:n])
			if sni != "" {
				log.Printf("Sniffed TLS SNI: %s", sni)
			}
			program := SniffRequestProgram(clientConn)
			if program != "" {
				log.Printf("Sniffed Program: %s", program)
			}
			_, _ = dstConn.Write(buf[:n])
		}
		if err == nil {
			_, _ = io.Copy(dstConn, clientConn)
		}
		dstConn.Close()
		clientConn.Close()
	}()
	_, _ = io.Copy(clientConn, dstConn)
	clientConn.Close()
	dstConn.Close()
	return
}

func SniffHTTPHost(data []byte) string {
	reader := bufio.NewReader(bytes.NewReader(data))
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	if !strings.Contains(firstLine, "HTTP/1.1") {
		return ""
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "Host: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Host: "))
		}
	}
	return ""
}

func SniffTLSSNI(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 || !IsValidTLSVersion(data[1], data[2]) {
		return ""
	}

	headerLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+headerLen > len(data) {
		return ""
	}

	domain, err := ReadClientHello(data[5 : 5+headerLen])
	if err != nil {
		return ""
	}
	return domain
}

func IsValidTLSVersion(major, minor byte) bool {
	return major == 3
}

// ReadClientHello returns server name (if any) from TLS client hello message.
// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go#L300
func ReadClientHello(data []byte) (string, error) {
	if len(data) < 42 {
		return "", errors.New("no Clue")
	}
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return "", errors.New("no Clue")
	}
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return "", errors.New("no Clue")
	}

	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return "", errors.New("not Client Hello")
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return "", errors.New("no Clue")
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return "", errors.New("no Clue")
	}
	data = data[1+compressionMethodsLen:]

	if len(data) == 0 {
		return "", errors.New("not Client Hello")
	}
	if len(data) < 2 {
		return "", errors.New("not Client Hello")
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return "", errors.New("not Client Hello")
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return "", errors.New("not Client Hello")
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return "", errors.New("not Client Hello")
		}

		if extension == 0x00 { /* extensionServerName */
			d := data[:length]
			if len(d) < 2 {
				return "", errors.New("not Client Hello")
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return "", errors.New("not Client Hello")
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return "", errors.New("not Client Hello")
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return "", errors.New("not Client Hello")
				}
				if nameType == 0 {
					serverName := string(d[:nameLen])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(serverName, ".") {
						return "", errors.New("not Client Hello")
					}
					return serverName, nil
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}

	return "", errors.New("not TLS")
}

func getPIDFromConnection(conn *net.TCPConn) (int, error) {
	// Get the local address of the connection
	clientAddr := conn.RemoteAddr().(*net.TCPAddr)

	// Determine which proc file to read based on IP version
	procFile := "/proc/net/tcp"
	if clientAddr.IP.To4() == nil {
		procFile = "/proc/net/tcp6"
	}

	// Read the appropriate proc file
	file, err := os.Open(procFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	reader := bufio.NewScanner(file)
	for reader.Scan() {
		line := reader.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse the local address
		localAddress := fields[1]
		localIPPort := strings.Split(localAddress, ":")
		if len(localIPPort) != 2 {
			continue
		}

		// Handle IPv4 and IPv6 addresses
		var localIP net.IP
		var err error
		if clientAddr.IP.To4() != nil {
			localIP, err = hexToIPv4(localIPPort[0])
		} else {
			localIP, err = hexToIPv6(localIPPort[0])
		}

		if err != nil || !localIP.Equal(clientAddr.IP) {
			continue
		}

		localPort, err := strconv.ParseUint(localIPPort[1], 16, 16)
		if err != nil || localPort != uint64(clientAddr.Port) {
			continue
		}

		// Get the inode number from the line
		inode := fields[9]

		// Find the PID by inode
		pid, err := findPIDByInode(inode)
		if err == nil {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("PID not found")
}

func hexToIPv4(hexStr string) (net.IP, error) {
	bytes := make([]byte, 4)
	_, err := fmt.Sscanf(hexStr, "%2x%2x%2x%2x", &bytes[3], &bytes[2], &bytes[1], &bytes[0])
	if err != nil {
		return nil, err
	}
	return net.IP(bytes), nil
}

func hexToIPv6(hexStr string) (net.IP, error) {
	bytes := make([]byte, 16)
	_, err := fmt.Sscanf(hexStr, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		&bytes[3], &bytes[2], &bytes[1], &bytes[0],
		&bytes[7], &bytes[6], &bytes[5], &bytes[4],
		&bytes[11], &bytes[10], &bytes[9], &bytes[8],
		&bytes[15], &bytes[14], &bytes[13], &bytes[12])
	if err != nil {
		return nil, err
	}
	return net.IP(bytes), nil
}

// Function to find PID by inode number
func findPIDByInode(inode string) (int, error) {
	// Look through all PIDs in /proc
	procDir := "/proc"
	pids, err := os.ReadDir(procDir)
	if err != nil {
		return 0, err
	}

	for _, pidDir := range pids {
		if !pidDir.IsDir() || !isNumeric(pidDir.Name()) {
			continue
		}

		fdDir := filepath.Join(procDir, pidDir.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			fdPath := filepath.Join(fdDir, fd.Name())
			link, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}
			if strings.Contains(link, inode) {
				pid, err := strconv.Atoi(pidDir.Name())
				if err == nil {
					return pid, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("PID not found")
}

// Function to check if a string is numeric
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Function to get the program name from the PID
func getProgramNameFromPID(pid int) (string, error) {
	cmdPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	cmd, err := os.ReadFile(cmdPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(cmd)), nil
}

// Function to sniff the request program
func SniffRequestProgram(conn *net.TCPConn) string {
	// Check if the connection is from localhost
	clientAddr := conn.RemoteAddr().(*net.TCPAddr).IP
	if !(clientAddr.IsLoopback()) {
		return ""
	}

	// Check if the OS is Linux
	if runtime.GOOS != "linux" {
		return ""
	}

	// Get the PID of the process that initiated the connection
	pid, err := getPIDFromConnection(conn)
	if err != nil {
		//log.Printf("Failed to get PID: %v", err)
		return ""
	}

	// Get the program name from the PID
	program, err := getProgramNameFromPID(pid)
	if err != nil {
		//log.Printf("Failed to get program name from PID: %v", err)
		return ""
	}

	return program
}

func (h *TCPOnlyHandler) HandleUDPAssociate(s *Server, request *Request, clientConn *net.TCPConn) error {
	return ErrNotImplemented
}

func (h *TCPOnlyHandler) HandleUDP(s *Server, datagram *Datagram, clientAddr *net.UDPAddr) error {
	return ErrNotImplemented
}

func (h *TCPOnlyHandler) createAssociation(UDPListener *net.UDPConn, clientAddr *net.UDPAddr) (*net.UDPConn, error) {
	return nil, ErrNotImplemented
}

func (h *TCPOnlyHandler) Start() error {
	return nil
}

func (h *TCPOnlyHandler) Stop() error {
	return nil
}

func NewTCPOnlyHandler() *TCPOnlyHandler {
	return &TCPOnlyHandler{}
}
