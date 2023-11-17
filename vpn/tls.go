package vpn

import (
    "bufio"
    "crypto/tls"
    "encoding/binary"
    "net/http"
    "sslcon/base"
    "sslcon/proto"
    "sslcon/session"
    "time"
)

// 复用已有的 tls.Conn 和对应的 bufR
func tlsChannel(conn *tls.Conn, bufR *bufio.Reader, cSess *session.ConnSession, resp *http.Response) {
    defer func() {
        base.Info("tls channel exit")
        resp.Body.Close()
        _ = conn.Close()
        cSess.Close()
    }()
    var (
        err           error
        bytesReceived int
        dataLen       uint16
        dead          = time.Duration(cSess.TLSDpdTime+5) * time.Second
    )

    go payloadOutTLSToServer(conn, cSess)

    // Step 21 serverToPayloadIn
    // 读取服务器返回的数据，调整格式，放入 cSess.PayloadIn
    for {
        // 重置超时限制
        if cSess.ResetTLSReadDead.Load() {
            _ = conn.SetReadDeadline(time.Now().Add(dead))
            cSess.ResetTLSReadDead.Store(false)
        }

        pl := getPayloadBuffer()                // 从池子申请一块内存，存放去除头部的数据包到 PayloadIn，在 payloadInToTun 中释放
        bytesReceived, err = bufR.Read(pl.Data) // 服务器没有数据返回时，会阻塞
        if err != nil {
            base.Error("tls server to payloadIn error:", err)
            return
        }

        // base.Debug("tls server to payloadIn", "Type", pl.Data[6])
        // https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.2
        switch pl.Data[6] {
        case 0x00: // DATA
            // base.Debug("tls receive DATA")
            // 获取数据长度
            dataLen = binary.BigEndian.Uint16(pl.Data[4:6])
            // 去除数据头
            copy(pl.Data, pl.Data[8:8+dataLen])
            // 更新切片长度
            pl.Data = pl.Data[:dataLen]

            select {
            case cSess.PayloadIn <- pl:
            case <-cSess.CloseChan:
                return
            }
        case 0x04:
            base.Debug("tls receive DPD-RESP")
        case 0x03: // DPD-REQ
            pl.Type = 0x04
            select {
            case cSess.PayloadOutTLS <- pl:
            case <-cSess.CloseChan:
                return
            }
        }
        cSess.Stat.BytesReceived += uint64(bytesReceived)
    }
}

// payloadOutTLSToServer Step 4
func payloadOutTLSToServer(conn *tls.Conn, cSess *session.ConnSession) {
    defer func() {
        base.Info("tls payloadOut to server exit")
        _ = conn.Close()
        cSess.Close()
    }()

    var (
        err       error
        bytesSent int
        pl        *proto.Payload
    )

    for {
        select {
        case pl = <-cSess.PayloadOutTLS:
        case <-cSess.CloseChan:
            return
        }

        // base.Debug("tls payloadOut to server", "Type", pl.Type)
        if pl.Type == 0x00 {
            // 获取数据长度
            l := len(pl.Data)
            // 先扩容 +8
            pl.Data = pl.Data[:l+8]
            // 数据后移
            copy(pl.Data[8:], pl.Data)
            // 添加头信息
            copy(pl.Data[:8], proto.Header)
            // 更新头长度
            binary.BigEndian.PutUint16(pl.Data[4:6], uint16(l))
        } else {
            pl.Data = append(pl.Data[:0], proto.Header...)
            // 设置头类型
            pl.Data[6] = pl.Type
        }
        bytesSent, err = conn.Write(pl.Data)
        if err != nil {
            base.Error("tls payloadOut to server error:", err)
            return
        }
        cSess.Stat.BytesSent += uint64(bytesSent)

        // 释放由 tunToPayloadOut 申请的内存
        putPayloadBuffer(pl)
    }
}
