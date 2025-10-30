package main

import "C"
import (
	"encoding/json"
	"io"
	"net/http"

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
	testNet()
	return nil
}

//export vpnConnect
func vpnConnect(jsonProfile, password string) *C.char {
	base.Debug(jsonProfile)
	err := json.Unmarshal([]byte(jsonProfile), auth.Prof)
	if err != nil {
		return C.CString(err.Error())
	}
	// in case of jsonProfile does not allow saving passwords
	if password != "" {
		auth.Prof.Password = password
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
	if status != nil {
		return C.CString(string(status))
	}
	return nil
}

//export vpnDisConnect
func vpnDisConnect() {
	api.DisConnect()
}

func testNet() {
	// 定义请求的 URL
	url := "http://ip.jsontest.com"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		base.Debug("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应的内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		base.Debug("读取响应失败: %v", err)
	}

	// 打印响应状态和内容
	base.Debug("响应状态:", resp.Status)
	base.Debug("响应内容:")
	base.Debug(string(body))
}
