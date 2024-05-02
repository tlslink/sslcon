module sslcon

go 1.21

require (
	github.com/elastic/go-sysinfo v1.13.1
	github.com/gopacket/gopacket v1.2.0
	github.com/gorilla/websocket v1.5.1
	github.com/jackpal/gateway v1.0.13
	github.com/kardianos/service v1.2.2
	github.com/lysShub/wintun-go v0.0.0-20240131112415-8f3bf638af49
	github.com/pion/dtls/v2 v2.2.8-0.20240201071732-2597464081c8
	github.com/sourcegraph/jsonrpc2 v0.2.0
	github.com/spf13/cobra v1.8.0
	github.com/tlslink/simplejson v0.0.0-20230709141507-130316fc6e67
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20240223175432-6ab7f5a3765c
	go.uber.org/atomic v1.11.0
	golang.org/x/crypto v0.21.0
	golang.org/x/net v0.23.0
	golang.org/x/sys v0.18.0
	golang.zx2c4.com/wireguard/windows v0.5.3
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/ebitengine/purego v0.5.1 // indirect
	github.com/elastic/go-windows v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/lysShub/dll-go v0.0.0-20240131092034-3f09ae5eff72 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v3 v3.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.1 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/term v0.18.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v0.0.0-20181124034731-591f970eefbb // indirect
)

replace github.com/kardianos/service v1.2.2 => github.com/cuonglm/service v0.0.0-20230322120818-ee0647d95905
