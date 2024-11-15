//go:build windows || (linux && !android) || (darwin && !ios)

package main

import "sslcon/cmd"

func main() {
	cmd.Execute()
}
