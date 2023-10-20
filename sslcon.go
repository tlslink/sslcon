//go:build linux || darwin || windows

package main

import "vpnagent/cmd"

func main() {
    cmd.Execute()
}
