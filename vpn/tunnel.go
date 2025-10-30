package vpn

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"sslcon/auth"
	"sslcon/base"
	"sslcon/session"
	"sslcon/utils"
	"sslcon/utils/vpnc"
)

var (
	reqHeaders = make(map[string]string)
	tunnel     *http.Response
)

func init() {
	reqHeaders["X-CSTP-VPNAddress-Type"] = "IPv4"
	// Payload + 8 + 加密扩展位 + TCP或UDP头 + IP头 最好小于 1500，这里参考 AnyConnect 设置
	reqHeaders["X-CSTP-MTU"] = "1399"
	reqHeaders["X-CSTP-Base-MTU"] = "1399"
	// if base.Cfg.OS == "android" || base.Cfg.OS == "ios" {
	//    reqHeaders["X-CSTP-License"] = "mobile"
	// }
}

func initTunnel() {
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04#name-server-response-and-tunnel-
	reqHeaders["Cookie"] = "webvpn=" + session.Sess.SessionToken // 无论什么服务端都需要通过 Cookie 发送 Session
	reqHeaders["X-CSTP-Local-VPNAddress-IP4"] = base.LocalInterface.Ip4

	// Legacy Establishment of Secondary UDP Channel https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04#name-the-secondary-dtls-channel-
	// worker-vpn.c WSPCONFIG(ws)->udp_port != 0 && req->master_secret_set != 0 否则 disabling UDP (DTLS) connection
	// 如果开启 dtls_psk（默认开启，见配置说明） 且 CipherSuite 包含 PSK-NEGOTIATE（仅限ocserv），worker-http.c 自动设置 req->master_secret_set = 1
	// 此时无需手动设置 Secret，会自动协商建立 dtls 链接，AnyConnect 客户端不支持
	session.Sess.PreMasterSecret, _ = utils.MakeMasterSecret()
	reqHeaders["X-DTLS-Master-Secret"] = hex.EncodeToString(session.Sess.PreMasterSecret) // A hex encoded pre-master secret to be used in the legacy DTLS session negotiation

	// https://gitlab.com/openconnect/ocserv/-/blob/master/src/worker-http.c#L150
	// https://github.com/openconnect/openconnect/blob/master/gnutls-dtls.c#L75
	reqHeaders["X-DTLS12-CipherSuite"] = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256"
}

// SetupTunnel initiates an HTTP CONNECT command to establish a VPN
func SetupTunnel() error {
	initTunnel()

	// https://github.com/golang/go/commit/da6c168378b4c1deb2a731356f1f438e4723b8a7
	// https://github.com/golang/go/issues/17227#issuecomment-341855744
	req, _ := http.NewRequest("CONNECT", auth.Prof.Scheme+auth.Prof.HostWithPort+"/CSCOSSLC/tunnel", nil)
	utils.SetCommonHeader(req)
	for k, v := range reqHeaders {
		// req.Header.Set 会将首字母大写，其它小写
		req.Header[k] = []string{v}
	}

	// 发送 CONNECT 请求
	err := req.Write(auth.Conn)
	if err != nil {
		auth.Conn.Close()
		return err
	}

	// resp.Body closed when tlsChannel exit
	tunnel, err = http.ReadResponse(auth.BufR, req)
	if err != nil {
		auth.Conn.Close()
		return err
	}

	if tunnel.StatusCode != http.StatusOK {
		auth.Conn.Close()
		return fmt.Errorf("tunnel negotiation failed %s", tunnel.Status)
	}

	// 提前判断是否调试模式，避免不必要的转换，http.ReadResponse.Header 将首字母大写，其余小写，即使服务端调试时正常
	if base.Cfg.LogLevel == "Debug" {
		headers := make([]byte, 0)
		buf := bytes.NewBuffer(headers)
		// http.ReadResponse: Keys in the map are canonicalized (see CanonicalHeaderKey).
		// https://ron-liu.medium.com/what-canonical-http-header-mean-in-golang-2e97f854316d
		_ = tunnel.Header.Write(buf)
		base.Debug(buf.String())
	}

	// 协商成功，读取服务端返回的配置
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04#name-tunnel-and-channels-establi

	cSess := session.Sess.NewConnSession(&tunnel.Header)
	cSess.ServerAddress = strings.Split(auth.Conn.RemoteAddr().String(), ":")[0]
	cSess.Hostname = auth.Prof.Host
	cSess.TLSCipherSuite = tls.CipherSuiteName(auth.Conn.ConnectionState().CipherSuite)

	base.Info("tls channel negotiation succeeded")

	// go 不存在条件编译，要么用 垃圾代码+dummy 内容，要么用独立文件
	// runtime.GOOS 实际值为编译时的 GOOS，如编译时为 ios，即使在 mac 上运行也是 ios
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" /*|| runtime.GOOS == "darwin"*/ {
		// 只有 tun 和路由设置成功才会进行下一步
		err = setupTun(0)
		if err != nil {
			auth.Conn.Close()
			cSess.Close()
			return err
		}

		// 为了靠谱，不再异步设置，路由多的话可能要等等
		err = vpnc.SetRoutes(cSess)
		if err != nil {
			auth.Conn.Close()
			cSess.Close()
			return err
		}

		SetupChannel()
	}

	return nil
}

func SetupTun(fd int) error {
	cSess := session.Sess.CSess

	err := setupTun(fd)
	if err != nil {
		auth.Conn.Close()
		cSess.Close()
		return err
	}
	return nil
}

func SetupChannel() {
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04#name-the-primary-cstp-channel-tc
	go tlsChannel()

	if !base.Cfg.NoDTLS {
		// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04#name-the-secondary-dtls-channel-
		go dtlsChannel()
	}

	cSess := session.Sess.CSess

	cSess.DPDTimer()
	cSess.ReadDeadTimer()
}

func Status() []byte {
	cSess := session.Sess.CSess
	if cSess != nil {
		status, _ := json.Marshal(cSess)
		base.Debug(string(status))

		return status
	}
	return nil
}

// DisConnect 主动断开或者 ctrl+c，不包括网络或tun异常退出
func DisConnect() {
	session.Sess.ActiveClose = true
	cSess := session.Sess.CSess

	if cSess != nil {
		vpnc.ResetRoutes(cSess)
		cSess.Close()
	}
}
