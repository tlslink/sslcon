//go:build android || ios

package vpn

import (
	"os"
	"runtime"

	"sslcon/base"
	"sslcon/proto"
	"sslcon/session"
	"sslcon/tun"
)

var offset = 0 // reserve space for header

func setupTun(fd int) error {
	cSess := session.Sess.CSess

	var tunFile *os.File
	if runtime.GOOS == "android" {
		tunFile = os.NewFile(uintptr(fd), "/dev/net/tun")
	} else {
		tunFile = os.NewFile(uintptr(fd), "")
	}
	dev, err := tun.CreateTUNFromFile(tunFile, cSess.MTU)
	if err != nil {
		base.Error("failed to creates a new tun interface")
		return err
	}
	if runtime.GOOS == "darwin" {
		offset = 4
	}

	cSess.TunName, _ = dev.Name()
	base.Debug("tun device:", cSess.TunName)
	tun.NativeTunDevice = dev.(*tun.NativeTun)

	// the tun device should already be configured

	// go tunToPayloadOut(dev, cSess) // read from apps
	// go payloadInToTun(dev, cSess)  // write to apps

	return nil
}

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
		n, err = dev.Read(pl.Data, offset) // 如果 tun 没有 up，会在这等待
		if err != nil {
			base.Error("tun to payloadOut error:", err)
			return
		}

		// 更新数据长度
		pl.Data = (pl.Data)[offset : offset+n]

		// base.Debug("tunToPayloadOut")
		// if base.Cfg.LogLevel == "Debug" {
		//     src, srcPort, dst, dstPort := utils.ResolvePacket(pl.Data)
		//     if dst == "8.8.8.8" {
		//         base.Debug("client from", src, srcPort, "request target", dst, dstPort)
		//     }
		// }

		dSess := cSess.DSess
		if cSess.DtlsConnected.Load() {
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

func payloadInToTun(dev tun.Device, cSess *session.ConnSession) {
	// tun 设备写错误或者cSess.CloseChan
	defer func() {
		base.Info("payloadIn to tun exit")
		// 可能由写错误触发，和 tunToPayloadOut 一起，只要有一处确保退出 cSess 即可，否则 tls 不会退出
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

		// base.Debug("payloadInToTun")
		// if base.Cfg.LogLevel == "Debug" {
		//     src, srcPort, dst, dstPort := utils.ResolvePacket(pl.Data)
		//     if src == "8.8.8.8" {
		//         base.Debug("target from", src, srcPort, "response to client", dst, dstPort)
		//     }
		// }

		if offset > 0 {
			expand := make([]byte, offset+len(pl.Data))
			copy(expand[offset:], pl.Data)
			_, err = dev.Write(expand, offset)
		} else {
			_, err = dev.Write(pl.Data, offset)
		}

		if err != nil {
			base.Error("payloadIn to tun error:", err)
			return
		}

		// 释放由 serverToPayloadIn 申请的内存
		putPayloadBuffer(pl)
	}
}
