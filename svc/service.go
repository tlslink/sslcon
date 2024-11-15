package svc

import (
	"fmt"
	"runtime"

	"github.com/kardianos/service"
	"sslcon/api"
	"sslcon/base"
	"sslcon/rpc"
)

type program struct{}

var logger service.Logger

var (
	serviceConfig *service.Config
	prg           = &program{}
)

func init() {
	svcName := "sslcon"
	if runtime.GOOS == "windows" {
		svcName = "SSLCon"
	}
	serviceConfig = &service.Config{
		Name:        svcName,
		DisplayName: "SSLCon VPN Agent",
		Description: "SSLCon SSL VPN service Agent",
	}
}

// Start should not block. Do the actual work async.
func (p program) Start(s service.Service) error {
	if service.Interactive() {
		logger.Info("Running in terminal.")
	} else {
		logger.Info("Running under service manager.")
	}
	go p.run()
	return nil
}

// Stop should not block. Return with a few seconds.
func (p program) Stop(s service.Service) error {
	logger.Info("I'm Stopping!")
	base.Info("Stop")
	api.DisConnect()
	return nil
}

func (p program) run() {
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
		err = svc.Stop()
		if err != nil {
			fmt.Println("Cannot stop the service: " + err.Error())
		}
		err = svc.Uninstall()
		if err != nil {
			fmt.Println("Cannot uninstall the service: " + err.Error())
		}
	}
}
