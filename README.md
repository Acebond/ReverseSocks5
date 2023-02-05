# ReverseSocks5
Reverse socks5 proxy over TLS in Golang using https://github.com/things-go/go-socks5 and https://github.com/hashicorp/yamux.

# Usage

## Start Server
```
ReverseSocks5 -socks "127.0.0.1:1080" -listen ":10443" -cert localhost.pem -key localhost-key.pem
```
This will open the socks5 port on `127.0.0.1:1080` and listen for an agent on `:10443`. Note the socks5 port will only be accessible once an agent connects.

## Start Client/Agent
```
ReverseSocks5 -connect "server.goes.here:10443" -k
```
This will connect to the server and be the egress point for the socks5 traffic, effectively exposing the internal network of the client/agent to anyone who can access the socks5 port on the server. Note that `-k` accepts any certificate presented by the server and any host name in that certificate.

## Generate Self-Signed Certificate
```
openssl req -x509 -newkey rsa:4096 -keyout localhost-key.pem -out localhost.pem -sha256 -days 365 -nodes
```
