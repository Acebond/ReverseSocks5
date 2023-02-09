# ReverseSocks5
Reverse socks5 proxy over TLS in Golang using https://github.com/things-go/go-socks5 and https://github.com/hashicorp/yamux. Could be useful to bypass firewalls.

# Usage

## Start Server
```
Usage: ReverseSocks5 server [flags]
  -cert string
        Certificate file for the socks server (default "CreateCertificate")
  -key string
        Private key file for the socks server (default "GenerateKey")
  -listen string
        Listen address for socks agents address:port (default ":10443")
  -socks string
        Listen address for socks server address:port (default "127.0.0.1:1080")

Example:
ReverseSocks5 server
OR 
ReverseSocks5 server -socks "127.0.0.1:1080" -listen ":10443" -cert localhost.pem -key localhost-key.pem
```
This will open the socks5 port on `127.0.0.1:1080` and listen for an agent on `:10443`. Note the socks5 port will only be accessible once an agent connects. If no certificate and private key are provided, ReverseSocks5 will generate a self-signed certificate.

## Start Agent
```
Usage: ReverseSocks5 agent [flags]
  -connect string
        Connect address for socks agent address:port
  -k    Allow insecure server connections on the socks agent
  -proxy string
        Proxy address for the socks agent schema://address:port. Supports http/https/socks5.

Example:
ReverseSocks5 agent -connect "server.goes.here:10443" -k
OR
ReverseSocks5 agent -connect "server.goes.here:10443" -k -proxy "http://internal.network.proxy:8080"
```
This will connect to the server and be the egress point for the socks5 traffic, effectively exposing the internal network of the agent to anyone who can access the socks5 port on the server. Note that `-k` accepts any certificate presented by the server and any host name in that certificate, this is required if self-signed certificates are used.

## Optionally Generate Self-Signed Certificate using OpenSSL
```
openssl req -x509 -newkey rsa:4096 -keyout localhost-key.pem -out localhost.pem -sha256 -days 365 -nodes
```
