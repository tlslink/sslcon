package auth

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "encoding/xml"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "sslcon/base"
    "sslcon/proto"
    "sslcon/session"
    "sslcon/utils"
    "strings"
    "text/template"
    "time"
)

var (
    Prof         = &Profile{Initialized: false}
    Conn         *tls.Conn // tls.Conn 是结构体，net.Conn 是接口，所以这里可以用指针类型
    BufR         *bufio.Reader
    reqHeaders   = make(map[string]string)
    WebVpnCookie string
)

// Profile 模板变量字段必须导出，虽然全局，但每次连接都被重置
type Profile struct {
    Host      string `json:"host"`
    Username  string `json:"username"`
    Password  string `json:"password"`
    Group     string `json:"group"`
    SecretKey string `json:"secret"`

    Initialized bool
    AppVersion  string // for report to server in xml

    HostWithPort string
    Scheme       string
    AuthPath     string

    MacAddress  string
    TunnelGroup string
    GroupAlias  string
    ConfigHash  string
}

const (
    tplInit = iota
    tplAuthReply
)

func init() {
    reqHeaders["X-Transcend-Version"] = "1"
    reqHeaders["X-Aggregate-Auth"] = "1"

    Prof.Scheme = "https://"
}

// InitAuth 确定用户组和服务端认证地址 AuthPath
func InitAuth() error {
    WebVpnCookie = ""
    // https://github.com/mwitkow/go-http-dialer
    config := tls.Config{
        InsecureSkipVerify: base.Cfg.InsecureSkipVerify,
    }
    var err error
    Conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp4", Prof.HostWithPort, &config)
    if err != nil {
        return err
    }
    BufR = bufio.NewReader(Conn)
    // base.Info(Conn.ConnectionState().Version)

    dtd := new(proto.DTD)

    Prof.AppVersion = base.Cfg.AgentVersion
    Prof.MacAddress = base.LocalInterface.Mac

    err = tplPost(tplInit, "", dtd)
    if err != nil {
        return err
    }
    Prof.AuthPath = dtd.Auth.Form.Action
    if Prof.AuthPath == "" {
        Prof.AuthPath = "/"
    }
    Prof.TunnelGroup = dtd.Opaque.TunnelGroup
    Prof.GroupAlias = dtd.Opaque.GroupAlias
    Prof.ConfigHash = dtd.Opaque.ConfigHash

    gps := len(dtd.Auth.Form.Groups)
    if gps != 0 && !utils.InArray(dtd.Auth.Form.Groups, Prof.Group) {
        return fmt.Errorf("available user groups are: %s", strings.Join(dtd.Auth.Form.Groups, " "))
    }

    return nil
}

// PasswordAuth 认证成功后，服务端新建 ConnSession，并生成 SessionToken 或者通过 Header 返回 WebVpnCookie
func PasswordAuth() error {
    dtd := new(proto.DTD)
    // 发送用户名或者用户名+密码
    err := tplPost(tplAuthReply, Prof.AuthPath, dtd)
    if err != nil {
        return err
    }
    // 兼容两步登陆，如必要则再次发送
    if dtd.Type == "auth-request" && dtd.Auth.Error.Value == "" {
        dtd = new(proto.DTD)
        err = tplPost(tplAuthReply, Prof.AuthPath, dtd)
        if err != nil {
            return err
        }
    }
    // 用户名、密码等错误
    if dtd.Type == "auth-request" {
        if dtd.Auth.Error.Value != "" {
            return fmt.Errorf(dtd.Auth.Error.Value, dtd.Auth.Error.Param1)
        }
        return errors.New(dtd.Auth.Message)
    }

    // AnyConnect 客户端支持 XML，OpenConnect 不使用 XML，而是使用 Cookie 反馈给客户端登陆状态
    session.Sess.SessionToken = dtd.SessionToken
    // 兼容 OpenConnect
    if WebVpnCookie != "" {
        session.Sess.SessionToken = WebVpnCookie
    }
    base.Debug("SessionToken:" + session.Sess.SessionToken)
    return nil
}

// 渲染模板并发送请求
func tplPost(typ int, path string, dtd *proto.DTD) error {
    tplBuffer := new(bytes.Buffer)
    if typ == tplInit {
        t, _ := template.New("init").Parse(templateInit)
        _ = t.Execute(tplBuffer, Prof)
    } else {
        t, _ := template.New("auth_reply").Parse(templateAuthReply)
        _ = t.Execute(tplBuffer, Prof)
    }
    if base.Cfg.LogLevel == "Debug" {
        post := tplBuffer.String()
        if typ == tplAuthReply {
            post = utils.RemoveBetween(post, "<auth>", "</auth>")
        }
        base.Debug(post)
    }
    url := fmt.Sprintf("%s%s%s", Prof.Scheme, Prof.HostWithPort, path)
    if Prof.SecretKey != "" {
        url += "?" + Prof.SecretKey
    }
    req, _ := http.NewRequest("POST", url, tplBuffer)

    utils.SetCommonHeader(req)
    for k, v := range reqHeaders {
        req.Header[k] = []string{v}
    }

    err := req.Write(Conn)
    if err != nil {
        Conn.Close()
        return err
    }

    var resp *http.Response
    resp, err = http.ReadResponse(BufR, req)
    if err != nil {
        Conn.Close()
        return err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        Conn.Close()
        return err
    }
    if base.Cfg.LogLevel == "Debug" {
        base.Debug(string(body))
    }

    if resp.StatusCode == http.StatusOK {
        err = xml.Unmarshal(body, dtd)
        if dtd.Type == "complete" && dtd.SessionToken == "" {
            // 兼容 ocserv
            cookies := resp.Cookies()
            if len(cookies) != 0 {
                for _, c := range cookies {
                    if c.Name == "webvpn" {
                        WebVpnCookie = c.Value
                        break
                    }
                }
            }
        }
        // nil
        return err
    }
    Conn.Close()
    return fmt.Errorf("auth error %s", resp.Status)
}

var templateInit = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>dummy</device-id>
</config-auth>`

// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.2.2
var templateAuthReply = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>dummy</device-id>
    <opaque is-for="sg">
        <tunnel-group>{{.TunnelGroup}}</tunnel-group>
        <group-alias>{{.GroupAlias}}</group-alias>
        <config-hash>{{.ConfigHash}}</config-hash>
    </opaque>
    <mac-address-list>
        <mac-address public-interface="true">{{.MacAddress}}</mac-address>
    </mac-address-list>
    <auth>
        <username>{{.Username}}</username>
        <password>{{.Password}}</password>
    </auth>
    <group-select>{{.Group}}</group-select>
</config-auth>`
