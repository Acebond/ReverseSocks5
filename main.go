package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/hashicorp/yamux"
	"github.com/magisterquis/connectproxy"
	"github.com/things-go/go-socks5"
	"golang.org/x/net/proxy"
)

func Usage(serverCmd, agentCmd *flag.FlagSet) {
	fmt.Printf("Usage: ReverseSocks5 server [flags]\n")
	serverCmd.PrintDefaults()
	fmt.Println()
	fmt.Printf("Usage: ReverseSocks5 agent [flags]\n")
	agentCmd.PrintDefaults()
	fmt.Println()
	os.Exit(1)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var (
		serverCmd = flag.NewFlagSet("server", flag.ExitOnError)
		listen    = serverCmd.String("listen", ":10443", "Listen address for socks agents address:port")
		cert      = serverCmd.String("cert", "CreateCertificate", "Certificate filepath for the socks server")
		key       = serverCmd.String("key", "GenerateKey", "Private key filepath for the socks server")
		socks     = serverCmd.String("socks", "127.0.0.1:1080", "Listen address for socks server address:port")
		agentCmd  = flag.NewFlagSet("agent", flag.ExitOnError)
		connect   = agentCmd.String("connect", "", "Connect address for socks agent address:port")
		proxy     = agentCmd.String("proxy", "", "Proxy address for the socks agent schema://address:port. Supports http/https/socks5.")
		insecure  = agentCmd.Bool("k", false, "Allow insecure server connections on the socks agent")
	)

	if len(os.Args) < 2 {
		Usage(serverCmd, agentCmd)
	}

	switch os.Args[1] {
	case serverCmd.Name():
		serverCmd.Parse(os.Args[2:])
		ReverseSocksServer(*listen, *cert, *key, *socks)
	case agentCmd.Name():
		agentCmd.Parse(os.Args[2:])
		ReverseSocksAgent(*connect, *proxy, *insecure)
	default:
		Usage(serverCmd, agentCmd)
	}
}

func ReverseSocksServer(listen, cert, key, socks string) {
	var cer tls.Certificate
	var err error
	if cert != "CreateCertificate" && key != "GenerateKey" {
		cer, err = tls.LoadX509KeyPair(cert, key)
	} else {
		log.Println("Generating a self-signed X.509 certificate")
		cer, err = MakeCert()
	}
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Listening for socks agents on " + listen)
	ListenForAgent(listen, socks, cer)
}

func ConnectUsingProxy(proxyString, address string) (net.Conn, error) {
	proxy.RegisterDialerType("http", connectproxy.New)
	proxy.RegisterDialerType("https", connectproxy.New)

	proxyURL, err := url.Parse(proxyString)
	if nil != err {
		return nil, err
	}

	d, err := proxy.FromURL(proxyURL, proxy.Direct)
	if nil != err {
		return nil, err
	}
	c, err := d.Dial("tcp", address)
	return c, err
}

// Start a socks5 server and tunnel the traffic to the server at address.
func ReverseSocksAgent(address, proxyString string, insecure bool) {
	tlsConfig := &tls.Config{InsecureSkipVerify: insecure}

	var conn *tls.Conn
	var err error

	log.Println("Connecting to socks server at " + address)

	if proxyString == "" {
		conn, err = tls.Dial("tcp", address, tlsConfig)
		if err != nil {
			log.Println(err.Error())
			return
		}
	} else {
		log.Println("Using proxy " + proxyString)
		proxiedConn, err := ConnectUsingProxy(proxyString, address)
		if err != nil {
			log.Println(err.Error())
			return
		}
		tlsConfig.ServerName = strings.Split(address, ":")[0]
		conn = tls.Client(proxiedConn, tlsConfig)
	}

	log.Println("Connected")
	AgentRun(conn)
}

func AgentRun(conn net.Conn) {
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
	log.Println("Listening for socks clients on " + listen)
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
