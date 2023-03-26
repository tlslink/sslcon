module vpnagent

go 1.20

require (
	github.com/gorilla/websocket v1.5.0
	github.com/pion/dtls/v2 v2.2.6
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/sourcegraph/jsonrpc2 v0.2.0
	golang.org/x/net v0.7.0
	golang.org/x/sys v0.5.1-0.20230222185716-a3b23cc77e89
	golang.zx2c4.com/wireguard/windows v0.5.3
)

require (
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.0.2 // indirect
	github.com/pion/udp/v2 v2.0.1 // indirect
	golang.org/x/crypto v0.6.0 // indirect
)

//replace golang.zx2c4.com/wintun => ./wintun
