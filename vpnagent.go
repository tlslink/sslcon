//go:build windows || (linux && !android) || (darwin && !ios)

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/service"
	"sslcon/api"
	"sslcon/base"
	"sslcon/rpc"
	"sslcon/svc"
)

func main() {
	// fmt.Println("os.Args: ", len(os.Args))
	if len(os.Args) < 2 {
		if service.Interactive() {
			base.Setup()
			rpc.Setup()
			watchSignal() // 主协程退出则应用退出
		} else {
			svc.RunSvc()
		}
	} else {
		cmd := os.Args[1]
		switch cmd {
		case "install":
			svc.InstallSvc()
		case "uninstall":
			svc.UninstallSvc()
			// todo uninstall wintun driver
		default:
			fmt.Println("invalid command: ", cmd)
		}
	}
}

func watchSignal() {
	base.Info("Server pid: ", os.Getpid())

	sigs := make(chan os.Signal, 1)
	// https://pkg.go.dev/os/signal
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	for {
		// 没有信号就阻塞，从而避免主协程退出
		sig := <-sigs
		base.Info("Get signal:", sig)
		switch sig {
		default:
			base.Info("Stop")
			api.DisConnect()
			return
		}
	}
}
