package main

import "C"
import (
	"encoding/json"

	"sslcon/api"
	"sslcon/auth"
	"sslcon/base"
)

func main() {}

//export vpnInit
func vpnInit(jsonConfig string) *C.char {
	err := json.Unmarshal([]byte(jsonConfig), &base.Cfg)
	if err != nil {
		// shouldn't bee freeing the string just before you return it
		return C.CString(err.Error())
	}
	base.InitLog()
	base.Debug(jsonConfig)
	return nil
}

//export vpnConnect
func vpnConnect(jsonProfile string) *C.char {
	base.Debug(jsonProfile)
	err := json.Unmarshal([]byte(jsonProfile), auth.Prof)
	if err != nil {
		return C.CString(err.Error())
	}
	auth.Prof.Initialized = true
	err = api.Connect()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export vpnReConnect
func vpnReConnect() *C.char {
	err := api.SetupTunnel(true)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export vpnSetupTun
func vpnSetupTun(fd int) *C.char {
	err := api.SetupTun(fd)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export vpnSetupChannel
func vpnSetupChannel() {
	api.SetupChannel()
}

//export vpnStatus
func vpnStatus() *C.char {
	status := api.Status()
	return C.CString(string(status))
}

//export vpnDisConnect
func vpnDisConnect() {
	api.DisConnect()
}
