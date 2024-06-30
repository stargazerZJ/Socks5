package Socks5_test

import (
	"encoding/hex"
	"github.com/miekg/dns"
	"github.com/stargazerZJ/Socks5"
	"github.com/txthinking/socks5"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestServerStart(t *testing.T) {
	s, err := Socks5.NewServer("127.0.0.1:1082", false, "", "", true, Socks5.NewDefaultHandler())
	if err != nil {
		log.Println(err)
		return
	}
	err = s.ListenAndServe()
	if err != nil {
		log.Println(err)
		return
	}
	// #Output:
}

func TestServerStartAndStop(t *testing.T) {
	s, err := Socks5.NewServer("127.0.0.1:1082", false, "", "", true, Socks5.NewDefaultHandler())
	if err != nil {
		log.Println(err)
		return
	}

	go func() {
		err = s.ListenAndServe()
		if err != nil {
			log.Println(err)
			return
		}
	}()

	// Set up channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received
	sig := <-sigChan
	log.Println("Received signal:", sig)

	// Stop the server
	err = s.Shutdown()
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Server stopped successfully")
}

func ExampleClient_tcp() {
	s, err := Socks5.NewServer("127.0.0.1:1082", false, "", "", true, Socks5.NewDefaultHandler())
	if err != nil {
		log.Println(err)
		return
	}
	defer s.Shutdown()
	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Println(err)
			return
		}
	}()
	c, err := socks5.NewClient("127.0.0.1:1082", "", "", 0, 60)
	if err != nil {
		log.Println(err)
		return
	}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return c.Dial(network, addr)
			},
		},
	}
	time.Sleep(500 * time.Millisecond)
	res, err := client.Get("https://ifconfig.co")
	if err != nil {
		log.Println(err)
		return
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("tcp", string(b))
	// Output:
}

func ExampleClient_udp() {
	s, err := Socks5.NewServer("127.0.0.1:1082", false, "", "", true, Socks5.NewDefaultHandler())
	if err != nil {
		log.Println(err)
		return
	}
	defer s.Shutdown()
	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Println(err)
			return
		}
	}()
	c, err := socks5.NewClient("127.0.0.1:1082", "", "", 0, 60)
	if err != nil {
		log.Println(err)
		return
	}
	time.Sleep(500 * time.Millisecond)
	conn, err := c.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Println(err)
		return
	}
	b, err := hex.DecodeString("0001010000010000000000000a74787468696e6b696e6703636f6d0000010001")
	if err != nil {
		log.Println(err)
		return
	}
	if _, err := conn.Write(b); err != nil {
		log.Println(err)
		return
	}
	b = make([]byte, 2048)
	n, err := conn.Read(b)
	if err != nil {
		log.Println(err)
		return
	}
	m := &dns.Msg{}
	if err := m.Unpack(b[0:n]); err != nil {
		log.Println(err)
		return
	}
	log.Println(m.String())
	// Output:
}
