package rpc

import (
    "strings"
    "vpnagent/auth"
    "vpnagent/session"
    "vpnagent/utils"
    "vpnagent/vpn"
)

// Connect 调用之前必须由前端填充 auth.Prof，建议填充 base.Interface
func Connect() error {
    if strings.Contains(auth.Prof.Host, ":") {
        auth.Prof.HostWithPort = auth.Prof.Host
    } else {
        auth.Prof.HostWithPort = auth.Prof.Host + ":443"
    }
    // 为适应复杂网络环境，必须能够感知网卡变化，建议由前端获取当前网络信息发送过来，而不是登陆前由 Go 处理
    if !auth.Prof.Initialized {
        err := utils.GetLocalInterface()
        if err != nil {
            return err
        }
    }

    err := auth.InitAuth()
    // 少写几个 return err
    if err == nil {
        err = auth.PasswordAuth()
        if err != nil {
            return err
        }
    }
    return SetupTunnel()
}

// SetupTunnel 操作系统长时间睡眠后再自动连接会失败，仅用于短时间断线自动重连
func SetupTunnel() error {
    return vpn.SetupTunnel()
}

func DisConnect() {
    session.Sess.ActiveClose = true
    if session.Sess.CSess != nil {
        session.Sess.CSess.Close()
    }
}
