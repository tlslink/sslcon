package rpc

import (
    "context"
    "encoding/json"
    "fmt"
    "github.com/gorilla/websocket"
    "github.com/sourcegraph/jsonrpc2"
    ws "github.com/sourcegraph/jsonrpc2/websocket"
    "net/http"
    "vpnagent/auth"
    "vpnagent/base"
    "vpnagent/session"
)

const (
    STATUS = iota
    CONFIG
    CONNECT
    DISCONNECT
    RECONNECT
    INTERFACE
    ABORT
    STAT
)

var (
    Clients         []*jsonrpc2.Conn
    rpcHandler      = handler{}
    connectedStr    string
    disconnectedStr string
)

type handler struct{}

func Setup() {
    go func() {
        http.HandleFunc("/rpc", rpc)
        // 无法启动则退出服务或应用
        base.Fatal(http.ListenAndServe(":6210", nil))
    }()
}

func rpc(resp http.ResponseWriter, req *http.Request) {
    up := websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
            return true
        },
    }
    conn, err := up.Upgrade(resp, req, nil)
    if err != nil {
        base.Error(err)
        return
    }
    defer conn.Close()

    jsonStream := ws.NewObjectStream(conn)
    // 此时 base.GetBaseLogger() 仍然是 Stdout，当前使用的 rpc 库无法在连接成功后修改 logger
    rpcConn := jsonrpc2.NewConn(req.Context(), jsonStream, &rpcHandler, jsonrpc2.SetLogger(base.GetBaseLogger()))
    Clients = append(Clients, rpcConn)
    <-rpcConn.DisconnectNotify()
    for i, c := range Clients {
        if c == rpcConn {
            Clients = append(Clients[:i], Clients[i+1:]...)
            base.Debug(fmt.Sprintf("client %d disconnected", i))
            break
        }
    }
}

// Handle ID 即方法
func (_ *handler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
    // request route
    switch req.ID.Num {
    case STAT:
        if session.Sess.Connected {
            _ = conn.Reply(ctx, req.ID, session.Sess.CSess.Stat)
            return
        }
        jError := jsonrpc2.Error{Code: 1, Message: disconnectedStr}
        _ = conn.ReplyWithError(ctx, req.ID, &jError)
    case STATUS:
        // 等待 DTLS 隧道创建过程结束，无论隧道是否建立成功
        <-session.Sess.CSess.DtlsSetupChan
        if session.Sess.Connected {
            _ = conn.Reply(ctx, req.ID, session.Sess.CSess)
            return
        }
        jError := jsonrpc2.Error{Code: 1, Message: disconnectedStr}
        _ = conn.ReplyWithError(ctx, req.ID, &jError)
    case CONNECT:
        // 启动时未连接，其它 UI 连接后再次调用
        if session.Sess.Connected {
            _ = conn.Reply(ctx, req.ID, connectedStr)
            return
        }
        err := json.Unmarshal(*req.Params, auth.Prof)
        if err != nil {
            jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
            _ = conn.ReplyWithError(ctx, req.ID, &jError)
            return
        }
        err = Connect()
        if err != nil {
            base.Error(err)
            jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
            _ = conn.ReplyWithError(ctx, req.ID, &jError)
            DisConnect()
            return
        }
        connectedStr = "connected to " + auth.Prof.Host
        disconnectedStr = "disconnected from " + auth.Prof.Host
        _ = conn.Reply(ctx, req.ID, connectedStr)
        go monitor()
    case RECONNECT:
        // UI 未检测到活动网络发生变化或者网络变化后已经推送接口信息
        if session.Sess.Connected {
            _ = conn.Reply(ctx, req.ID, connectedStr)
            return
        }
        err := SetupTunnel()
        if err != nil {
            base.Error(err)
            jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
            _ = conn.ReplyWithError(ctx, req.ID, &jError)
            DisConnect()
            return
        }
        _ = conn.Reply(ctx, req.ID, connectedStr)
        go monitor()
    case DISCONNECT:
        if session.Sess.Connected {
            DisConnect()
        }
        // may be exited normally by other clients
        _ = conn.Reply(ctx, jsonrpc2.ID{Num: DISCONNECT, IsString: false}, disconnectedStr)
    case CONFIG:
        // 初始化配置
        logLevel := base.Cfg.LogLevel
        logPath := base.Cfg.LogPath
        err := json.Unmarshal(*req.Params, &base.Cfg)
        if err != nil {
            jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
            _ = conn.ReplyWithError(ctx, req.ID, &jError)
            return
        }
        _ = conn.Reply(ctx, req.ID, "ready to connect")
        // 重置 logger，修改其它配置不影响
        if logLevel != base.Cfg.LogLevel || logPath != base.Cfg.LogPath {
            base.InitLog()
        }
    case INTERFACE:
        err := json.Unmarshal(*req.Params, base.LocalInterface)
        if err != nil {
            jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
            _ = conn.ReplyWithError(ctx, req.ID, &jError)
            return
        }
        auth.Prof.Initialized = true
        _ = conn.Reply(ctx, req.ID, "ready to connect")
    default:
        base.Debug("receive rpc call:", req)
        jError := jsonrpc2.Error{Code: 1, Message: "unknown method: " + req.Method}
        _ = conn.ReplyWithError(ctx, req.ID, &jError)
    }
}

func monitor() {
    // 不考虑 DTLS 中途关闭情形
    <-session.Sess.CloseChan
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    for _, conn := range Clients {
        if session.Sess.ActiveClose {
            _ = conn.Reply(ctx, jsonrpc2.ID{Num: DISCONNECT, IsString: false}, disconnectedStr)
        } else {
            _ = conn.Reply(ctx, jsonrpc2.ID{Num: ABORT, IsString: false}, disconnectedStr)
        }
    }
}
