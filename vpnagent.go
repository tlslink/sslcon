package main

import (
    "dtlslink/base"
    "dtlslink/rpc"
    "os"
    "os/signal"
    "syscall"
)

func main() {
    base.Setup()
    rpc.Setup()
    watchSignal() // 主协程退出则应用退出
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
            rpc.DisConnect()
            return
        }
    }
}
