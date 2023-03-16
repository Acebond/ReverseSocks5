package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"sync"

	"github.com/Acebond/gomux"
	"github.com/things-go/go-socks5"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	const version = 0.4
	log.Printf("ReverseSocks5 v%v\n", version)

	defaultPassword := "password"

	listen := flag.String("listen", ":10443", "Listen address for socks agents address:port")
	socks := flag.String("socks", "127.0.0.1:1080", "Listen address for socks server address:port")
	psk := flag.String("psk", defaultPassword, "Pre-shared key for encryption and authentication")
	connect := flag.String("connect", "", "Connect address for socks agent address:port")
	flag.Parse()

	if *connect == "" {
		ReverseSocksServer(*listen, *socks, *psk)
	} else {
		ReverseSocksAgent(*connect, *psk)
	}
}

// Start a socks5 server and tunnel the traffic to the server at address.
func ReverseSocksAgent(serverAddress, psk string) {
	log.Println("Connecting to socks server at " + serverAddress)
	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Connected")

	session := gomux.Server(conn, psk)
	server := socks5.NewServer()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Println(err.Error())
			break
		}
		go func() {
			if err := server.ServeConn(stream); err != nil && err != gomux.ErrPeerClosedStream {
				log.Println(err.Error())
			}
			if err := stream.Close(); err != nil {
				log.Println(err.Error())
			}
		}()
	}

	if err := session.Close(); err != nil {
		log.Println(err.Error())
	}
}

func ReverseSocksServer(agentListenAddress, socksListenAddress, psk string) {
	log.Println("Listening for socks agents on " + agentListenAddress)
	ln, err := net.Listen("tcp", agentListenAddress)
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		session := gomux.Client(conn, psk)
		TunnelServer(socksListenAddress, session)
	}
}

// Accepts connections and tunnels the traffic to the SOCKS server running on the client.
func TunnelServer(listenAddress string, session *gomux.Mux) {
	log.Println("Listening for socks clients on " + listenAddress)
	addr, err := net.ResolveTCPAddr("tcp", listenAddress)
	if err != nil {
		log.Fatalln(err.Error())
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalln(err.Error())
	}

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			} else {
				log.Println(err.Error())
				continue
			}
		}

		stream, err := session.OpenStream()
		if err != nil {
			conn.Close()
			log.Println(err.Error())
			// This is unrecoverable as the socks server is not opening connections.
			break
		}

		go proxy(conn, stream)
	}

	if err := session.Close(); err != nil {
		log.Println(err.Error())
	}
	if err := ln.Close(); err != nil {
		log.Println(err.Error())
	}
}

func proxy(conn1 *net.TCPConn, conn2 *gomux.Stream) {
	defer conn1.Close()
	defer conn2.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn1, conn2)
		// Signal peer that no more data is coming.
		conn1.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn2, conn1)
		// Signal peer that no more data is coming.
		conn2.CloseWrite()
	}()

	wg.Wait()
}
