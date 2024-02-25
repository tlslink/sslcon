package utils

import (
    "crypto/rand"
    "fmt"
    "github.com/pion/dtls/v2/pkg/protocol"
    "net"
    "net/http"
    "os"
    "regexp"
    "runtime"
    "sslcon/base"
    "sslcon/utils/waterutil"
    "strings"
)

func InArray(arr []string, str string) bool {
    for _, d := range arr {
        if d == str {
            return true
        }
    }
    return false
}

func InArrayGeneric(arr []string, str string) bool {
    for _, d := range arr {
        if d != "" && strings.HasSuffix(str, d) {
            return true
        }
    }
    return false
}

// SetCommonHeader 认证和建立隧道都需要的 HTTP Header
// ocserv worker-http.c case HEADER_USER_AGENT 通过 strncasecmp() 函数比较前 n 个字符
func SetCommonHeader(req *http.Request) {
    if base.Cfg.CiscoCompat || base.Cfg.AgentName == "" {
        base.Cfg.AgentName = "AnyConnect"
    }
    req.Header.Set("User-Agent", fmt.Sprintf("%s %s %s", base.Cfg.AgentName, FirstUpper(runtime.GOOS), base.Cfg.AgentVersion))
    req.Header.Set("Content-Type", "application/xml")
}

func IpMask2CIDR(ip, mask string) string {
    length, _ := net.IPMask(net.ParseIP(mask).To4()).Size()
    return fmt.Sprintf("%s/%v", ip, length)
}

// IpMaskToCIDR 输入 192.168.1.10/255.255.255.255 返回 192.168.1.10/32
func IpMaskToCIDR(ipMask string) string {
    ips := strings.Split(ipMask, "/")
    length, _ := net.IPMask(net.ParseIP(ips[1]).To4()).Size()
    return fmt.Sprintf("%s/%v", ips[0], length)
}

func ResolvePacket(packet []byte) (string, uint16, string, uint16) {
    src := waterutil.IPv4Source(packet)
    srcPort := waterutil.IPv4SourcePort(packet)
    dst := waterutil.IPv4Destination(packet)
    dstPort := waterutil.IPv4DestinationPort(packet)
    return src.String(), srcPort, dst.String(), dstPort
}

func MakeMasterSecret() ([]byte, error) {
    masterSecret := make([]byte, 48)
    masterSecret[0] = protocol.Version1_2.Major
    masterSecret[1] = protocol.Version1_2.Minor
    _, err := rand.Read(masterSecret[2:])
    return masterSecret, err
}

func Min(init int, other ...int) int {
    min := init
    for _, val := range other {
        if val != 0 && val < min {
            min = val
        }
    }
    return min
}

func Max(init int, other ...int) int {
    max := init
    for _, val := range other {
        if val > max {
            max = val
        }
    }
    return max
}

func CopyFile(dstName, srcName string) (err error) {
    input, err := os.ReadFile(srcName)
    if err != nil {
        return err
    }

    err = os.WriteFile(dstName, input, 0644)
    if err != nil {
        return err
    }
    return nil
}

func FirstUpper(s string) string {
    if s == "" {
        return ""
    }
    return strings.ToUpper(s[:1]) + s[1:]
}

func RemoveBetween(input, start, end string) string {
    // 构建正则表达式模式，"(?s)" 包括换行符
    pattern := "(?s)" + regexp.QuoteMeta(start) + ".*?" + regexp.QuoteMeta(end)
    r := regexp.MustCompile(pattern)
    return r.ReplaceAllString(input, "")
}
