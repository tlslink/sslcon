package vpn

import (
    "runtime"
    "vpnagent/base"
    "vpnagent/proto"
    "vpnagent/session"
    "vpnagent/tun"
    "vpnagent/utils"
)

func setupTun(cSess *session.ConnSession) error {
    if runtime.GOOS == "windows" {
        cSess.TunName = "AnyLink"
    } else {
        cSess.TunName = "anylink"
    }
    dev, err := tun.CreateTUN(cSess.TunName, cSess.MTU)
    if err != nil {
        base.Error("failed to creates a new tun interface")
        return err
    }
    base.Debug("tun device:", cSess.TunName)

    tun.NativeTunDevice = dev.(*tun.NativeTun)
    err = utils.ConfigInterface(cSess.VPNAddress, cSess.VPNMask, cSess.ServerAddress, cSess.DNS,
        cSess.SplitInclude, cSess.SplitExclude)
    if err != nil {
        _ = dev.Close()
        return err
    }

    go tunToPayloadOut(dev, cSess) // read from apps
    go payloadInToTun(dev, cSess)  // write to apps
    return nil
}

// Step 3
// 网络栈将应用数据包转给 tun 后，该函数从 tun 读取数据包，放入 cSess.PayloadOutTLS 或 cSess.PayloadOutDTLS
// 之后由 payloadOutTLSToServer 或 payloadOutDTLSToServer 调整格式，发送给服务端
func tunToPayloadOut(dev tun.Device, cSess *session.ConnSession) {
    // tun 设备读错误
    defer func() {
        base.Info("tun to payloadOut exit")
        _ = dev.Close()
    }()
    var (
        err error
        n   int
    )

    for {
        // 从池子申请一块内存，存放到 PayloadOutTLS 或 PayloadOutDTLS，在 payloadOutTLSToServer 或 payloadOutDTLSToServer 中释放
        // 由 payloadOutTLSToServer 或 payloadOutDTLSToServer 添加 header 后发送出去
        pl := getPayloadBuffer()
        n, err = dev.Read(pl.Data, 0) // 如果 tun 没有 up，会在这等待
        if err != nil {
            base.Error("tun to payloadOut error:", err)
            return
        }

        // 更新数据长度
        pl.Data = (pl.Data)[:n]

        // base.Debug("tunToPayloadOut")
        // if base.Cfg.LogLevel == "Debug" {
        //    src, srcPort, dst, dstPort := utils.ResolvePacket(pl.Data)
        //    //if ip_src.String() == "192.168.1.2" {
        //    fmt.Println("client from", src, srcPort, "request target", dst, dstPort)
        //    //}
        // }

        dSess := cSess.DtlsSession
        if dSess != nil {
            select {
            case cSess.PayloadOutDTLS <- pl:
            case <-dSess.CloseChan:
            }
        } else {
            select {
            case cSess.PayloadOutTLS <- pl:
            case <-cSess.CloseChan:
                return
            }
        }
    }
}

// Step 22
// 读取 tlsChannel、dtlsChannel 放入 cSess.PayloadIn 的数据包（由服务端返回，已调整格式），写入 tun，网络栈交给应用
func payloadInToTun(dev tun.Device, cSess *session.ConnSession) {
    // tun 设备写错误或者cSess.CloseChan
    defer func() {
        base.Info("payloadIn to tun exit")
        // 可能由写错误触发，和 tunRead 一起，只要有一处确保退出 cSess 即可
        // 如果由外部触发，cSess.Close() 因为使用 sync.Once，所以没影响
        cSess.Close()
        _ = dev.Close()
    }()

    var (
        err error
        pl  *proto.Payload
    )

    for {
        select {
        case pl = <-cSess.PayloadIn:
        case <-cSess.CloseChan:
            return
        }

        _, err = dev.Write(pl.Data, 0)
        if err != nil {
            base.Error("payloadIn to tun error:", err)
            return
        }

        // base.Debug("payloadInToTun")
        // if base.Cfg.LogLevel == "Debug" {
        //    src, srcPort, dst, dstPort := utils.ResolvePacket(pl.Data)
        //    //if ip_dst.String() == "192.168.1.2" {
        //    fmt.Println("target from", src, srcPort, "response to client", dst, dstPort)
        //    //}
        // }

        // 释放由 serverToPayloadIn 申请的内存
        putPayloadBuffer(pl)
    }
}
