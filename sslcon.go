//go:build linux || darwin || windows

package main

import "sslcon/cmd"

func main() {
	cmd.Execute()
}
