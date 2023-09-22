module vpnagent

go 1.20

require (
	github.com/gorilla/websocket v1.5.0
	github.com/kardianos/service v1.2.2
	github.com/pion/dtls/v2 v2.2.7
	github.com/sourcegraph/jsonrpc2 v0.2.0
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20230420174744-55c8b9515a01
	golang.org/x/net v0.14.0
	golang.org/x/sys v0.11.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	golang.zx2c4.com/wireguard/windows v0.5.3
)

require (
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v3 v3.0.1 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	golang.org/x/crypto v0.12.0 // indirect
)

replace github.com/pion/dtls/v2 => ./dtls
