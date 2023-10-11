

## vpnagent

This is a Golang implementation of the [OpenConnect VPN Protocol](https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03) for client side development. 

For desktop OS, similar to Cisco Secure Client's vpnagentd, it should be run as a separate background service with root privileges, so that the front-end UI does not require an administrator authorization every time it starts. 

The API is exposed through the WebSocket and JSON-RPC 2.0 protocols. Anyone can use any front-end tool to implement their own GUI.

**[There](https://github.com/tlslink/anylink-client) is an example showing how to use this project.**

Currently the following servers are supported,

- [ocserv](https://gitlab.com/openconnect/ocserv)
- [anylink](https://github.com/bjdgyc/anylink)

## CLI

```
$ ./cli
A CLI application that supports the OpenConnect SSL VPN protocol.
For more information, please visit https://github.com/tlslink/vpnagent

Usage:
  cli [flags]
  cli [command]

Available Commands:
  config      Set up VPN service
  connect     Connect to the VPN server
  disconnect  Disconnect from the VPN server
  status      Get VPN connection information

Flags:
  -h, --help   help for cli

Use "cli [command] --help" for more information about a command.
```

### install

```shell
sudo ./vpnagent install
# or
sudo ./vpnagent uninstall
```
the installed service on linux

```
sudo systemctl stop/start/restart AnyLink.service
sudo systemctl disable/enable AnyLink.service
```

### connect

```bash
./cli connect --host test.com -u vpn -g default -p
```

### disconnect

```
./cli disconnect
```

### status

```
./cli status
```

### config

```
./cli config -l debug -d "/tmp"
```

## APIs

You can use any WebSocket tool to test the [API](https://github.com/tlslink/vpnagent/blob/main/rpc/rpc.go).

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
    "log_path": ""
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
