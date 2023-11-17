package vpn

import (
    "context"
    "encoding/hex"
    "github.com/pion/dtls/v2"
    "net"
    "strconv"
    "time"
    "vpnagent/base"
    "vpnagent/ciphersuite"
    "vpnagent/proto"
    "vpnagent/session"
)

// 新建 dtls.Conn
func dtlsChannel(cSess *session.ConnSession) {
    var (
        conn          *dtls.Conn
        dSess         *session.DtlsSession
        err           error
        bytesReceived int
        dead          = time.Duration(cSess.DTLSDpdTime+5) * time.Second
    )
    defer func() {
        base.Info("dtls channel exit")
        if conn != nil {
            _ = conn.Close()
        }
        if dSess != nil {
            dSess.Close()
        }
    }()

    port, _ := strconv.Atoi(cSess.DTLSPort)
    addr := &net.UDPAddr{IP: net.ParseIP(cSess.ServerAddress), Port: port}

    id, _ := hex.DecodeString(cSess.DTLSId)

    config := &dtls.Config{
        InsecureSkipVerify:   true,
        ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
        CipherSuites: func() []dtls.CipherSuiteID {
            switch cSess.DTLSCipherSuite {
            case "ECDHE-ECDSA-AES128-GCM-SHA256":
                return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
            case "ECDHE-RSA-AES128-GCM-SHA256":
                return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
            case "ECDHE-ECDSA-AES256-GCM-SHA384":
                return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
            case "ECDHE-RSA-AES256-GCM-SHA384":
                return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
            default:
                return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
            }
        }(),
        // 兼容旧版本 ocserv
        CustomCipherSuites: func() []dtls.CipherSuite {
            return []dtls.CipherSuite{&ciphersuite.TLSRsaWithAes128GcmSha256{}}
        },
        SessionStore: &SessionStore{dtls.Session{ID: id, Secret: session.Sess.PreMasterSecret}},
        // PSK: func(hint []byte) ([]byte, error) {
        //     // return []byte{0xAB, 0xC1, 0x23}, nil
        //     return id, nil
        // },
        // PSKIdentityHint: id,
    }
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    conn, err = dtls.DialWithContext(ctx, "udp4", addr, config)
    if err != nil {
        base.Error(err)
        close(cSess.DtlsSetupChan) // 没有成功建立 DTLS 隧道
        return
    }

    cSess.DtlsConnected.Store(true)
    dSess = cSess.DSess
    close(cSess.DtlsSetupChan) // 成功建立 DTLS 隧道

    if conn.ConnectionState().CipherSuiteID == ciphersuite.TLS_RSA_WITH_AES_128_GCM_SHA256 {
        cSess.DTLSCipherSuite = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    } else {
        cSess.DTLSCipherSuite = dtls.CipherSuiteName(conn.ConnectionState().CipherSuiteID)
    }
    base.Info("dtls channel negotiation succeeded")

    go payloadOutDTLSToServer(conn, dSess, cSess)

    // Step 21 serverToPayloadIn
    // 读取服务器返回的数据，调整格式，放入 cSess.PayloadIn，不再用子协程是为了能够退出 dtlsChannel 协程
    for {
        // 重置超时限制
        if cSess.ResetDTLSReadDead.Load() {
            _ = conn.SetReadDeadline(time.Now().Add(dead))
            cSess.ResetDTLSReadDead.Store(false)
        }

        pl := getPayloadBuffer()                // 从池子申请一块内存，存放去除头部的数据包到 PayloadIn，在 payloadInToTun 中释放
        bytesReceived, err = conn.Read(pl.Data) // 服务器没有数据返回时，会阻塞
        if err != nil {
            base.Error("dtls server to payloadIn error:", err)
            return
        }

        // base.Debug("dtls server to payloadIn")
        // https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.3
        // UDP 数据包的头部只有 1 字节
        switch pl.Data[0] {
        case 0x07: // KEEPALIVE
            // base.Debug("dtls receive KEEPALIVE")
        case 0x05: // DISCONNECT
            // base.Debug("dtls receive DISCONNECT")
            return
        case 0x03: // DPD-REQ
            // base.Debug("dtls receive DPD-REQ")
            pl.Type = 0x04
            select {
            case cSess.PayloadOutDTLS <- pl:
            case <-dSess.CloseChan:
            }
        case 0x04:
            base.Debug("dtls receive DPD-RESP")
        case 0x00: // DATA
            pl.Data = append(pl.Data[:0], pl.Data[1:bytesReceived]...)
            select {
            case cSess.PayloadIn <- pl:
            case <-dSess.CloseChan:
                return
            }
        }
        cSess.Stat.BytesReceived += uint64(bytesReceived)
    }
}

// payloadOutDTLSToServer Step 4
func payloadOutDTLSToServer(conn *dtls.Conn, dSess *session.DtlsSession, cSess *session.ConnSession) {
    defer func() {
        base.Info("dtls payloadOut to server exit")
        _ = conn.Close()
        dSess.Close()
    }()

    var (
        err       error
        bytesSent int
        pl        *proto.Payload
    )

    for {
        select {
        case pl = <-cSess.PayloadOutDTLS:
        case <-dSess.CloseChan:
            return
        }

        // base.Debug("dtls payloadOut to server")
        if pl.Type == 0x00 {
            // 获取数据长度
            l := len(pl.Data)
            // 先扩容 +1
            pl.Data = pl.Data[:l+1]
            // 数据后移
            copy(pl.Data[1:], pl.Data)
            // 添加头信息
            pl.Data[0] = pl.Type
        } else {
            // 设置头类型
            pl.Data = append(pl.Data[:0], pl.Type)
        }

        bytesSent, err = conn.Write(pl.Data)
        if err != nil {
            base.Error("dtls payloadOut to server error:", err)
            return
        }
        cSess.Stat.BytesSent += uint64(bytesSent)

        // 释放由 tunToPayloadOut 申请的内存
        putPayloadBuffer(pl)
    }
}

type SessionStore struct {
    sess dtls.Session
}

func (store *SessionStore) Set([]byte, dtls.Session) error {
    return nil
}

func (store *SessionStore) Get([]byte) (dtls.Session, error) {
    return store.sess, nil
}

func (store *SessionStore) Del([]byte) error {
    return nil
}
