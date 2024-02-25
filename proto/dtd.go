package proto

import "encoding/xml"

// DTD 基于 XML 的客户端、服务端请求和响应数据结构
// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#appendix-C.1
type DTD struct {
    XMLName              xml.Name       `xml:"config-auth"`
    Client               string         `xml:"client,attr"`                 // 一般都是 vpn
    Type                 string         `xml:"type,attr"`                   // 请求类型 init logout auth-reply
    AggregateAuthVersion string         `xml:"aggregate-auth-version,attr"` // 一般都是 2
    Version              string         `xml:"version"`                     // 客户端版本号
    GroupAccess          string         `xml:"group-access"`                // 请求的地址
    GroupSelect          string         `xml:"group-select"`                // 选择的组名
    SessionToken         string         `xml:"session-token"`
    Auth                 auth           `xml:"auth"`
    DeviceId             deviceId       `xml:"device-id"`
    Opaque               opaque         `xml:"opaque"`
    MacAddressList       macAddressList `xml:"mac-address-list"`
    Config               config         `xml:"config"`
}

type auth struct {
    Username string    `xml:"username"`
    Password string    `xml:"password"`
    Message  string    `xml:"message"`
    Banner   string    `xml:"banner"`
    Error    authError `xml:"error"`
    Form     form      `xml:"form"`
}

type form struct {
    Action string   `xml:"action,attr"`
    Groups []string `xml:"select>option"`
}

type authError struct {
    Param1 string `xml:"param1,attr"`
    Value  string `xml:",chardata"`
}

type deviceId struct {
    ComputerName    string `xml:"computer-name,attr"`
    DeviceType      string `xml:"device-type,attr"`
    PlatformVersion string `xml:"platform-version,attr"`
    UniqueId        string `xml:"unique-id,attr"`
    UniqueIdGlobal  string `xml:"unique-id-global,attr"`
}

type opaque struct {
    TunnelGroup string `xml:"tunnel-group"`
    GroupAlias  string `xml:"group-alias"`
    ConfigHash  string `xml:"config-hash"`
}

type macAddressList struct {
    MacAddress string `xml:"mac-address"`
}

type config struct {
    Opaque opaque2 `xml:"opaque"`
}

type opaque2 struct {
    CustomAttr customAttr `xml:"custom-attr"`
}

type customAttr struct {
    DynamicSplitExcludeDomains string `xml:"dynamic-split-exclude-domains"`
    DynamicSplitIncludeDomains string `xml:"dynamic-split-include-domains"`
}
