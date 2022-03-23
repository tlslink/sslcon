package base

import (
    "runtime"
)

var (
    Cfg            = &ClientConfig{}
    LocalInterface = &Interface{}
)

type ClientConfig struct {
    LogLevel           string `json:"log_level"`
    LogPath            string `json:"log_path"`
    InsecureSkipVerify bool   `json:"skip_verify"`
    AllowLAN           bool   `json:"allow_lan"`
    CiscoCompat        bool   `json:"cisco_compat"`
    OS                 string
}

// Interface 应该由外部接口设置
type Interface struct {
    Name    string `json:"name"`
    Ip4     string `json:"ip4"`
    Mac     string `json:"mac"`
    Gateway string `json:"gateway"`
}

func initCfg() {
    Cfg.LogLevel = "Debug"
    Cfg.InsecureSkipVerify = true
    Cfg.AllowLAN = true
    Cfg.CiscoCompat = true

    Cfg.OS = runtime.GOOS
}
