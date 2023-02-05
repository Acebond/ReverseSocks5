package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"

	"github.com/hashicorp/yamux"
	socks5 "github.com/things-go/go-socks5"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var (
		listen  = flag.String("listen", "", "listen address for socks agents address:port")
		cert    = flag.String("cert", "", "certificate file")
		key     = flag.String("key", "", "private key file")
		socks   = flag.String("socks", "127.0.0.1:1080", "listen address for socks server address:port")
		connect = flag.String("connect", "", "connect address for socks agent address:port")
	)
	flag.Parse()

	if *listen != "" && *cert != "" && *key != "" {
		cer, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatalln(err.Error())
		}
		log.Println("Listening for socks agents/clients")
		ListenForAgent(*listen, *socks, cer)
	} else if *connect != "" {
		log.Println("Connecting to socks server")
		ReverseSocksAgent(*connect)
	} else {
		flag.PrintDefaults()
	}
}

// Start a socks5 server and tunnel the traffic to the server at address.
func ReverseSocksAgent(address string) {
	config := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", address, config)
	if err != nil {
		log.Fatalln(err.Error())
	}

	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Fatalln(err.Error())
	}

	server := socks5.NewServer()

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Println(err.Error())
			break
		}
		go func() {
			if err := server.ServeConn(stream); err != nil {
				log.Println(err.Error())
			}
			if err := stream.Close(); err != nil {
				log.Println(err.Error())
			}
		}()
	}

	// This will call conn.Close() see https://github.com/hashicorp/yamux/blob/master/session.go#L289
	if err := session.Close(); err != nil {
		log.Println(err.Error())
	}
}

// Accepts connections and tunnels the traffic to the SOCKS server running on the client.
func TunnelServer(listen string, session *yamux.Session) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalln(err.Error())
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err.Error())
			break
		}

		stream, err := session.Open()
		if err != nil {
			conn.Close()
			log.Println(err.Error())
			// This is unrecoverable as the socks server is not opening connections.
			break
		}

		go func() {
			io.Copy(conn, stream)
			conn.Close()
		}()
		go func() {
			io.Copy(stream, conn)
			stream.Close()
		}()
	}

	if err := session.Close(); err != nil {
		log.Println(err.Error())
	}
	if err := ln.Close(); err != nil {
		log.Println(err.Error())
	}
}

func ListenForAgent(address, socks string, cert tls.Certificate) {
	config := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		Certificates:             []tls.Certificate{cert},
	}
	ln, err := tls.Listen("tcp", address, config)
	if err != nil {
		log.Fatalln(err.Error())
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err.Error())
			break
		}

		session, err := yamux.Client(conn, nil)
		if err != nil {
			conn.Close()
			log.Println(err.Error())
			continue
		}

		TunnelServer(socks, session)
	}

	if err := ln.Close(); err != nil {
		log.Println(err.Error())
	}
}
