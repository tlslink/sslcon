package session

import (
    "go.uber.org/atomic"
    "net/http"
    "sslcon/base"
    "sslcon/proto"
    "sslcon/utils"
    "strconv"
    "sync"
    "time"
)

var (
    Sess = &Session{}
)

type Session struct {
    SessionToken    string
    PreMasterSecret []byte

    ActiveClose bool
    CloseChan   chan struct{} // 用于通知所有 UI，ConnSession 已关闭
    CSess       *ConnSession
}

type stat struct {
    // be sure to use the double type when parsing
    BytesSent     uint64 `json:"bytesSent"`
    BytesReceived uint64 `json:"bytesReceived"`
}

// ConnSession used for both TLS and DTLS
type ConnSession struct {
    Sess *Session `json:"-"`

    ServerAddress     string
    LocalAddress      string
    Hostname          string
    TunName           string
    VPNAddress        string // The IPv4 address of the client
    VPNMask           string // IPv4 netmask
    DNS               []string
    MTU               int
    SplitInclude      []string
    SplitExclude      []string
    TLSCipherSuite    string
    TLSDpdTime        int // https://datatracker.ietf.org/doc/html/rfc3706
    TLSKeepaliveTime  int
    DTLSPort          string
    DTLSDpdTime       int
    DTLSKeepaliveTime int
    DTLSId            string `json:"-"` // used by the server to associate the DTLS channel with the CSTP channel
    DTLSCipherSuite   string
    Stat              *stat

    closeOnce      sync.Once           `json:"-"`
    CloseChan      chan struct{}       `json:"-"`
    PayloadIn      chan *proto.Payload `json:"-"`
    PayloadOutTLS  chan *proto.Payload `json:"-"`
    PayloadOutDTLS chan *proto.Payload `json:"-"`

    DtlsConnected *atomic.Bool
    DtlsSetupChan chan struct{} `json:"-"`
    DSess         *DtlsSession  `json:"-"`

    ResetTLSReadDead  *atomic.Bool `json:"-"`
    ResetDTLSReadDead *atomic.Bool `json:"-"`
}

type DtlsSession struct {
    closeOnce sync.Once
    CloseChan chan struct{}
}

func (sess *Session) NewConnSession(header *http.Header) *ConnSession {
    cSess := &ConnSession{
        Sess:              sess,
        LocalAddress:      base.LocalInterface.Ip4,
        Stat:              &stat{0, 0},
        closeOnce:         sync.Once{},
        CloseChan:         make(chan struct{}),
        DtlsSetupChan:     make(chan struct{}),
        PayloadIn:         make(chan *proto.Payload, 64),
        PayloadOutTLS:     make(chan *proto.Payload, 64),
        PayloadOutDTLS:    make(chan *proto.Payload, 64),
        DtlsConnected:     atomic.NewBool(false),
        ResetTLSReadDead:  atomic.NewBool(true),
        ResetDTLSReadDead: atomic.NewBool(true),
        DSess: &DtlsSession{
            closeOnce: sync.Once{},
            CloseChan: make(chan struct{}),
        },
    }
    sess.CSess = cSess

    sess.ActiveClose = false
    sess.CloseChan = make(chan struct{})

    cSess.VPNAddress = header.Get("X-CSTP-Address")
    cSess.VPNMask = header.Get("X-CSTP-Netmask")
    cSess.MTU, _ = strconv.Atoi(header.Get("X-CSTP-MTU"))
    cSess.DNS = header.Values("X-CSTP-DNS")
    // 如果服务器下发空字符串，字符串数组不会为 nil，会导致解析ip时报错
    cSess.SplitInclude = header.Values("X-CSTP-Split-Include")
    cSess.SplitExclude = header.Values("X-CSTP-Split-Exclude")
    // debug with https://ip.900cha.com/
    // cSess.SplitExclude = append(cSess.SplitExclude, "47.243.165.103/255.255.255.255")

    cSess.TLSDpdTime, _ = strconv.Atoi(header.Get("X-CSTP-DPD"))
    cSess.TLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-CSTP-Keepalive"))
    // https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.1.5.1
    cSess.DTLSId = header.Get("X-DTLS-Session-ID")
    if cSess.DTLSId == "" {
        // 兼容最新 ocserv
        cSess.DTLSId = header.Get("X-DTLS-App-ID")
    }
    cSess.DTLSPort = header.Get("X-DTLS-Port")
    cSess.DTLSDpdTime, _ = strconv.Atoi(header.Get("X-DTLS-DPD"))
    cSess.DTLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-DTLS-Keepalive"))
    if base.Cfg.NoDTLS {
        cSess.DTLSCipherSuite = "Unknown"
    } else {
        cSess.DTLSCipherSuite = header.Get("X-DTLS12-CipherSuite") // 连接前后格式不同
    }

    return cSess
}

func (cSess *ConnSession) DPDTimer() {
    go func() {
        defer func() {
            base.Info("dead peer detection timer exit")
        }()
        base.Debug("TLSDpdTime:", cSess.TLSDpdTime, "TLSKeepaliveTime", cSess.TLSKeepaliveTime,
            "DTLSDpdTime", cSess.DTLSDpdTime, "DTLSKeepaliveTime", cSess.DTLSKeepaliveTime)
        // 简化处理，最小15秒检测一次,至少5秒冗余
        dpdTime := utils.Min(cSess.TLSDpdTime, cSess.DTLSDpdTime) - 5
        if dpdTime < 10 {
            dpdTime = 10
        }
        tick := time.NewTicker(time.Duration(dpdTime) * time.Second)

        tlsDpd := proto.Payload{
            Type: 0x03,
            Data: make([]byte, 0, 8),
        }
        dtlsDpd := proto.Payload{
            Type: 0x03,
            Data: make([]byte, 0, 1),
        }

        for {
            select {
            case <-tick.C:
                // base.Debug("dead peer detection")
                select {
                case cSess.PayloadOutTLS <- &tlsDpd:
                default:
                }
                if cSess.DtlsConnected.Load() {
                    select {
                    case cSess.PayloadOutDTLS <- &dtlsDpd:
                    default:
                    }
                }
            case <-cSess.CloseChan:
                tick.Stop()
                return
            }
        }
    }()
}

func (cSess *ConnSession) ReadDeadTimer() {
    go func() {
        defer func() {
            base.Info("read dead timer exit")
        }()
        // 避免每次 for 循环都重置读超时的时间
        // 这里是绝对时间，至于链接本身，服务器没有数据时 conn.Read 会阻塞，有数据时会不断判断
        tick := time.NewTicker(4 * time.Second)
        for range tick.C {
            select {
            case <-cSess.CloseChan:
                tick.Stop()
                return
            default:
                cSess.ResetTLSReadDead.Store(true)
                cSess.ResetDTLSReadDead.Store(true)
            }
        }
    }()
}

func (cSess *ConnSession) Close() {
    cSess.closeOnce.Do(func() {
        if cSess.DtlsConnected.Load() {
            cSess.DSess.Close()
        }
        close(cSess.CloseChan)
        Sess.CSess = nil

        close(Sess.CloseChan)
    })
}

func (dSess *DtlsSession) Close() {
    dSess.closeOnce.Do(func() {
        close(dSess.CloseChan)
        if Sess.CSess != nil {
            Sess.CSess.DtlsConnected.Store(false)
            Sess.CSess.DTLSCipherSuite = ""
        }
    })
}
