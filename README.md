## vpnagent

This is a Golang implementation of the [OpenConnect VPN Protocol](https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03) for client side development. 

For desktop OS, similar to Cisco Secure Client's vpnagentd, it should be run as a separate background service with root privileges, so that the front-end UI does not require an administrator authorization every time it starts. The API is exposed through the WebSocket and JSON-RPC 2.0 protocols. Anyone can use any front-end tool to implement their own GUI.

For iOS and Android, it is **theoretically** possible to cross-compile to a dynamic link library.

> **Note**: The implementation of the VPN protocol itself has nothing to do with the routing table settings of the operating system. This repository contains simple [routing settings](https://github.com/dtlslink/vpnagent/blob/main/utils/utils_linux.go) under Linux. It would be great if someone has a more elegant implementation of cross-platform routing table operations.

Currently the following servers are supported,

- [ocserv](https://gitlab.com/openconnect/ocserv)
- [anylink](https://github.com/bjdgyc/anylink)

## APIs

The full VPN workflow test is currently only available under Linux, You can use any WebSocket tool to test the [API](https://github.com/dtlslink/vpnagent/blob/main/rpc/rpc.go).

ws://127.0.0.1:6210/rpc

### status

```json
{
  "jsonrpc": "2.0",
  "method": "status",
  "id": 0
}
```

### config

```json
{
  "jsonrpc": "2.0",
  "method": "config",
  "params": {
    "log_level": "Debug",
    "log_path": "/tmp/test.log"
  },
  "id": 1
}
```

### connect

```json
{
  "jsonrpc": "2.0",
  "method": "connect",
  "params": {
    "host": "vpn.test.com",
    "username": "vpn",
    "password": "123456",
    "group": ""
  },
  "id": 2
}
```

### disconnect

```json
{
  "jsonrpc": "2.0",
  "method": "disconnect",
  "id": 3
}
```

### reconnect

```json
{
  "jsonrpc": "2.0",
  "method": "reconnect",
  "id": 4
}
```

### stat

```json
{
  "jsonrpc": "2.0",
  "method": "stat",
  "id": 7
}
```
