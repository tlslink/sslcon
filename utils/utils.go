package utils

import (
	"crypto/rand"
	"fmt"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/songgao/water/waterutil"
	"net"
	"net/http"
	"strings"
	"vpnagent/base"
)

func InArray(arr []string, str string) bool {
	for _, d := range arr {
		if d == str {
			return true
		}
	}
	return false
}

// SetCommonHeader 认证和建立隧道都需要的 HTTP Header
// ocserv worker-http.c case HEADER_USER_AGENT 通过 strncasecmp() 函数比较前 n 个字符
func SetCommonHeader(req *http.Request) {
	if base.Cfg.CiscoCompat {
		req.Header.Set("User-Agent", "AnyConnect")
	} else {
		req.Header.Set("User-Agent", base.AppName+" "+base.AppVersion)
	}
}

func IpMask2CIDR(ip, mask string) string {
	length, _ := net.IPMask(net.ParseIP(mask).To4()).Size()
	return fmt.Sprintf("%s/%v", ip, length)
}

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
