package vpnc

import (
    "fmt"
    "github.com/jackpal/gateway"
    "net"
    "os/exec"
    "sslcon/base"
    "sslcon/session"
    "sslcon/utils"
    "strings"
)

var VPNAddress string

func ConfigInterface(cSess *session.ConnSession) error {
    VPNAddress = cSess.VPNAddress
    cmdStr1 := fmt.Sprintf("ifconfig %s inet %s %s netmask %s up", cSess.TunName, cSess.VPNAddress, cSess.VPNAddress, "255.255.255.255")
    err := execCmd([]string{cmdStr1})

    return err
}

func SetRoutes(cSess *session.ConnSession) error {
    cmdStr1 := fmt.Sprintf("route add -host %s %s", cSess.ServerAddress, base.LocalInterface.Gateway)
    err := execCmd([]string{cmdStr1})
    if err != nil {
        return err
    }
    // 默认路由通过 DNS 设置
    if len(cSess.SplitInclude) != 0 {
        for _, ipMask := range cSess.SplitInclude {
            dst := utils.IpMaskToCIDR(ipMask)
            cmdStr := fmt.Sprintf("route add -net %s %s", dst, cSess.VPNAddress)
            err = execCmd([]string{cmdStr})
            if err != nil {
                return routingError(dst, err)
            }
        }
    }

    if len(cSess.SplitExclude) > 0 {
        for _, ipMask := range cSess.SplitExclude {
            dst := utils.IpMaskToCIDR(ipMask)
            cmdStr := fmt.Sprintf("route add -net %s %s", dst, base.LocalInterface.Gateway)
            err = execCmd([]string{cmdStr})
            if err != nil {
                return routingError(dst, err)
            }
        }
    }

    // dns
    if len(cSess.DNS) > 0 {
        err = setDNS(cSess)
    }

    return err
}

func ResetRoutes(cSess *session.ConnSession) {
    // cmdStr1 := fmt.Sprintf("route delete default %s", cSess.VPNAddress)
    // cmdStr2 := fmt.Sprintf("route add default %s", base.LocalInterface.Gateway)

    cmdStr3 := fmt.Sprintf("route delete -host %s %s", cSess.ServerAddress, base.LocalInterface.Gateway)
    _ = execCmd([]string{cmdStr3})

    if len(cSess.SplitExclude) > 0 {
        for _, ipMask := range cSess.SplitExclude {
            dst := utils.IpMaskToCIDR(ipMask)
            cmdStr := fmt.Sprintf("route delete -net %s %s", dst, base.LocalInterface.Gateway)
            _ = execCmd([]string{cmdStr})
        }
    }

    if len(cSess.DynamicSplitExcludeDomains) > 0 {
        cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
            ips := value.([]string)
            for _, ip := range ips {
                dst := ip + "/32"
                cmdStr := fmt.Sprintf("route delete -net %s %s", dst, base.LocalInterface.Gateway)
                _ = execCmd([]string{cmdStr})
            }

            return true
        })
    }

    if len(cSess.DNS) > 0 {
        restoreDNS(cSess)
    }
}

func DynamicAddIncludeRoutes(ips []string) {
    for _, ip := range ips {
        dst := ip + "/32"
        cmdStr := fmt.Sprintf("route add -net %s %s", dst, VPNAddress)
        _ = execCmd([]string{cmdStr})
    }
}

func DynamicAddExcludeRoutes(ips []string) {
    for _, ip := range ips {
        dst := ip + "/32"
        cmdStr := fmt.Sprintf("route add -net %s %s", dst, base.LocalInterface.Gateway)
        _ = execCmd([]string{cmdStr})
    }
}

func GetLocalInterface() error {
    localInterfaceIP, err := gateway.DiscoverInterface()
    if err != nil {
        return err
    }
    gateway, err := gateway.DiscoverGateway()
    if err != nil {
        return err
    }

    localInterface := net.Interface{}

    ifaces, _ := net.Interfaces()
    for _, iface := range ifaces {
        addrs, _ := iface.Addrs()
        for _, addr := range addrs {
            ipnet, ok := addr.(*net.IPNet)
            if !ok {
                continue
            }

            ip := ipnet.IP.To4()
            if ip.Equal(localInterfaceIP) {
                localInterface = iface
                break
            }
        }
    }

    base.LocalInterface.Name = localInterface.Name
    base.LocalInterface.Ip4 = localInterfaceIP.String()
    base.LocalInterface.Gateway = gateway.String()
    base.LocalInterface.Mac = localInterface.HardwareAddr.String()

    base.Info("GetLocalInterface:", fmt.Sprintf("%+v", *base.LocalInterface))

    return nil
}

func routingError(dst string, err error) error {
    return fmt.Errorf("routing error: %s %s", dst, err)
}

func execCmd(cmdStrs []string) error {
    for _, cmdStr := range cmdStrs {
        cmd := exec.Command("sh", "-c", cmdStr)
        stdoutStderr, err := cmd.CombinedOutput()
        if err != nil {
            return fmt.Errorf("%s %s %s", err, cmd.String(), string(stdoutStderr))
        }
    }
    return nil
}

func setDNS(cSess *session.ConnSession) error {

    if len(cSess.DynamicSplitIncludeDomains) > 0 {
        DynamicAddIncludeRoutes(cSess.DNS)
    }

    var override string
    // 如果包含路由为空必为全局路由，如果使用包含域名，则包含路由必须填写一个，如 dns 地址
    if len(cSess.SplitInclude) == 0 {
        override = "d.add OverridePrimary # 1"
    }

    command := fmt.Sprintf(`
		open
		d.init
		d.add ServerAddresses * %s
        d.add SearchOrder 1
        d.add SupplementalMatchDomains * ""
		set State:/Network/Service/%s/DNS

		d.init
		d.add Router %s
		d.add Addresses * %s
		d.add InterfaceName %s
        %s
		set State:/Network/Service/%s/IPv4
		close
	`, strings.Join(cSess.DNS, " "), cSess.TunName, cSess.VPNAddress, cSess.VPNAddress, cSess.TunName, override, cSess.TunName)

    cmd := exec.Command("scutil")
    cmd.Stdin = strings.NewReader(command)

    // 执行命令并获取输出
    output, err := cmd.CombinedOutput()
    if err != nil {
        base.Error(err, output)
    }
    return err
}

func restoreDNS(cSess *session.ConnSession) {
    command := fmt.Sprintf(`
        open
        remove State:/Network/Service/%s/IPv4
        remove State:/Network/Service/%s/DNS
        close
	`, cSess.TunName, cSess.TunName)

    cmd := exec.Command("scutil")
    cmd.Stdin = strings.NewReader(command)

    // 执行命令并获取输出
    output, err := cmd.CombinedOutput()
    if err != nil {
        base.Error(err, output)
    }
}
