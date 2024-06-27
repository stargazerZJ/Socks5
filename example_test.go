package Socks5_test

import (
	"github.com/stargazerZJ/Socks5"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/txthinking/socks5"
)

func ExampleServer() {
	s, err := Socks5.NewServer("127.0.0.1:1082", false, "", "", false, &Socks5.DefaultHandler{})
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

func ExampleClient_tcp() {
	go ExampleServer()
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
	return // UDP is not supported for now
	/*
		go ExampleServer()
		c, err := socks5.NewClient("127.0.0.1:1080", "", "", 0, 60)
		if err != nil {
			log.Println(err)
			return
		}
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
	*/
}
