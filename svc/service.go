package svc

import (
    "fmt"
    "github.com/kardianos/service"
)

type initiate struct{}

var (
    serviceConfig = &service.Config{
        Name:        "AnyLink",
        DisplayName: "AnyLink Agent",
        Description: "AnyLink Secure Client Agent ",
    }
    prg = &initiate{}
)

// Start should not block. Do the actual work async.
func (p initiate) Start(s service.Service) error {
    return nil
}

// Stop should not block. Return with a few seconds.
func (p initiate) Stop(s service.Service) error {
    return nil
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
        // svc.Run()
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
