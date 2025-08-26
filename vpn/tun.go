package vpn

import (
	"runtime"
	"sync"

	"sslcon/base"
	"sslcon/proto"
	"sslcon/session"
	"sslcon/tun"
	"sslcon/utils"
	"sslcon/utils/vpnc"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var offset = 0 // reserve space for header

func setupTun(cSess *session.ConnSession) error {
	if runtime.GOOS == "windows" {
		cSess.TunName = "SSLCon"
	} else if runtime.GOOS == "darwin" {
		cSess.TunName = "utun"
		offset = 4
	} else {
		cSess.TunName = "sslcon"
	}
	dev, err := tun.CreateTUN(cSess.TunName, cSess.MTU)
	if err != nil {
		base.Error("failed to creates a new tun interface")
		return err
	}
	if runtime.GOOS == "darwin" {
		cSess.TunName, _ = dev.Name()
	}

	base.Debug("tun device:", cSess.TunName)
	tun.NativeTunDevice = dev.(*tun.NativeTun)

	// 不可并行
	err = vpnc.ConfigInterface(cSess)
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

// Step 22
// 读取 tlsChannel、dtlsChannel 放入 cSess.PayloadIn 的数据包（由服务端返回，已调整格式），写入 tun，网络栈交给应用
func payloadInToTun(dev tun.Device, cSess *session.ConnSession) {
	// tun 设备写错误或者cSess.CloseChan
	defer func() {
		base.Info("payloadIn to tun exit")
		if !cSess.Sess.ActiveClose {
			vpnc.ResetRoutes(cSess) // 如果 tun 没有创建成功，也不会调用 SetRoutes
		}
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

		// 只有当使用域名分流且返回数据包为 DNS 时才进一步分析，少建几个协程
		if cSess.DynamicSplitTunneling {
			_, srcPort, _, _ := utils.ResolvePacket(pl.Data)
			if srcPort == 53 {
				go dynamicSplitRoutes(pl.Data, cSess)
			}
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

func dynamicSplitRoutes(data []byte, cSess *session.ConnSession) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, _ := dnsLayer.(*layers.DNS)
	var answers []string
	if len(dns.Questions) > 0 && dns.ANCount > 0 {
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA {
				answers = append(answers, answer.IP.String())
			}
		}
	}
	if len(answers) == 0 {
		return
	}
	query := string(dns.Questions[0].Name)
	// base.Debug("Query:", query)

	// 域名拆分处理函数
	handleFunc := func(resolved *sync.Map, splitRoutesFunc func([]string)) {
		if old, ok := resolved.Load(query); !ok {
			// 第一次解析，更新缓存并修改路由
			resolved.Store(query, answers)
			splitRoutesFunc(answers)
		} else {
			// 已存在解析记录，找出新增的ip进行更新
			oldAnswers := old.([]string)
			oldSet := make(map[string]struct{})
			for _, ip := range oldAnswers {
				oldSet[ip] = struct{}{}
			}
			// 找出新增的IP
			var newAnswers []string
			for _, ip := range answers {
				if _, exists := oldSet[ip]; !exists {
					newAnswers = append(newAnswers, ip)
				}
			}
			if len(newAnswers) > 0 {
				// 合并新旧结果并更新缓存
				mergedAnswers := append(oldAnswers, newAnswers...)
				resolved.Store(query, mergedAnswers)
				// 处理新增的部分
				splitRoutesFunc(newAnswers)
			}
		}
	}

	// 使用域名拆分列表匹配当前查询的域名，命中则尝试更新路由规则
	if utils.InArrayGeneric(cSess.DynamicSplitIncludeDomains, query) {
		// 处理包含域名
		handleFunc(&cSess.DynamicSplitIncludeResolved, vpnc.DynamicAddIncludeRoutes)
	} else if utils.InArrayGeneric(cSess.DynamicSplitExcludeDomains, query) {
		// 处理排除域名
		handleFunc(&cSess.DynamicSplitExcludeResolved, vpnc.DynamicAddExcludeRoutes)
	}
}
