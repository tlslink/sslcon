package svc

import (
    "fmt"
    "github.com/kardianos/service"
    "vpnagent/base"
    "vpnagent/rpc"
)

type initiate struct{}

var logger service.Logger

var (
    serviceConfig = &service.Config{
        Name:        "AnyLink",
        DisplayName: "AnyLink Agent",
        Description: "AnyLink Secure Client Agent",
    }
    prg = &initiate{}
)

// Start should not block. Do the actual work async.
func (p initiate) Start(s service.Service) error {
    if service.Interactive() {
        logger.Info("Running in terminal.")
    } else {
        logger.Info("Running under service manager.")
    }
    go p.run()
    return nil
}

// Stop should not block. Return with a few seconds.
func (p initiate) Stop(s service.Service) error {
    logger.Info("I'm Stopping!")
    base.Info("Stop")
    rpc.DisConnect()
    return nil
}

func (p initiate) run() {
    base.Setup()
    rpc.Setup()
}

func RunSvc() {
    svc, err := service.New(prg, serviceConfig)
    if err != nil {
        fmt.Println("Cannot create the service: " + err.Error())
    }
    errs := make(chan error, 5)
    logger, err = svc.Logger(errs)
    if err != nil {
        fmt.Println("Cannot open a system logger: " + err.Error())
    }
    err = svc.Run()
    if err != nil {
        fmt.Println("Cannot start the service: " + err.Error())
    }
}

func InstallSvc() {
    svc, err := service.New(prg, serviceConfig)
    if err != nil {
        fmt.Println("Cannot create the service: " + err.Error())
    }
    err = svc.Install()
    if err != nil {
        fmt.Println("Cannot install the service: " + err.Error())
    } else {
        err := svc.Start()
        if err != nil {
            fmt.Println("Cannot start the service: " + err.Error())
        }
    }
}

func UninstallSvc() {
    svc, err := service.New(prg, serviceConfig)
    if err != nil {
        fmt.Println("Cannot create the service: " + err.Error())
    } else {
        err := svc.Stop()
        if err != nil {
            fmt.Println("Cannot stop the service: " + err.Error())
        }
        err = svc.Uninstall()
        if err != nil {
            fmt.Println("Cannot uninstall the service: " + err.Error())
        }
    }
}
