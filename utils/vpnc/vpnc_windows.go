package vpnc

import (
    "fmt"
    "golang.org/x/sys/windows"
    "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
    "net"
    "net/netip"
    "os/exec"
    "sslcon/base"
    "sslcon/session"
    "sslcon/tun"
    "sslcon/utils"
    "strings"
)

var (
    localInterface winipcfg.LUID
    iface          winipcfg.LUID
    nextHopVPN     netip.Addr
    nextHopGateway netip.Addr
)

func ConfigInterface(cSess *session.ConnSession) error {
    mtu, _ := tun.NativeTunDevice.MTU()
    err := SetMTU(cSess.TunName, mtu)
    if err != nil {
        return err
    }

    iface = winipcfg.LUID(tun.NativeTunDevice.LUID())

    // ip address
    iface.FlushIPAddresses(windows.AF_UNSPEC)

    nextHopVPN, _ = netip.ParseAddr(cSess.VPNAddress)
    prefixVPN, _ := netip.ParsePrefix(utils.IpMask2CIDR(cSess.VPNAddress, cSess.VPNMask))
    err = iface.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{prefixVPN})

    return err
}

func SetRoutes(cSess *session.ConnSession) error {
    // routes
    dst, err := netip.ParsePrefix(cSess.ServerAddress + "/32")
    nextHopGateway, _ = netip.ParseAddr(base.LocalInterface.Gateway)
    err = localInterface.AddRoute(dst, nextHopGateway, 5)
    if err != nil {
        return routingError(dst, err)
    }

    // Windows 排除路由 metric 相对大小好像不起作用，但不影响效果
    if len(cSess.SplitInclude) == 0 {
        cSess.SplitInclude = append(cSess.SplitInclude, "0.0.0.0/0.0.0.0")
    }
    for _, ipMask := range cSess.SplitInclude {
        dst, _ = netip.ParsePrefix(utils.IpMaskToCIDR(ipMask))
        err = iface.AddRoute(dst, nextHopVPN, 6)
        if err != nil {
            if strings.Contains(err.Error(), "already exists") {
                continue
            } else {
                return routingError(dst, err)
            }
        }
    }

    if len(cSess.SplitExclude) > 0 {
        for _, ipMask := range cSess.SplitExclude {
            dst, _ = netip.ParsePrefix(utils.IpMaskToCIDR(ipMask))
            err = localInterface.AddRoute(dst, nextHopGateway, 5)
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
    dst, _ := netip.ParsePrefix(cSess.ServerAddress + "/32")
    localInterface.DeleteRoute(dst, nextHopGateway)

    if len(cSess.SplitExclude) > 0 {
        for _, ipMask := range cSess.SplitExclude {
            dst, _ = netip.ParsePrefix(utils.IpMaskToCIDR(ipMask))
            localInterface.DeleteRoute(dst, nextHopGateway)
        }
    }

    if len(cSess.DynamicSplitExcludeDomains) > 0 {
        cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
            ips := value.([]string)
            for _, ip := range ips {
                dst, _ = netip.ParsePrefix(ip + "/32")
                localInterface.DeleteRoute(dst, nextHopGateway)
            }

            return true
        })
    }
}

func DynamicAddIncludeRoutes(ips []string) {
    for _, ip := range ips {
        dst, _ := netip.ParsePrefix(ip + "/32")
        _ = iface.AddRoute(dst, nextHopVPN, 6)
    }
}

func DynamicAddExcludeRoutes(ips []string) {
    for _, ip := range ips {
        dst, _ := netip.ParsePrefix(ip + "/32")
        _ = localInterface.AddRoute(dst, nextHopGateway, 5)
    }
}

func GetLocalInterface() error {
    ifcs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways)
    if err != nil {
        return err
    }

    var primaryInterface *winipcfg.IPAdapterAddresses
    for _, ifc := range ifcs {
        base.Debug(ifc.AdapterName(), ifc.Description(), ifc.FriendlyName(), ifc.Ipv4Metric, ifc.IfType)
        // exclude Virtual Ethernet and Loopback Adapter
        if !strings.Contains(ifc.Description(), "Virtual") {
            // https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/types.go?h=v0.5.3#n61
            if (ifc.IfType == 6 || ifc.IfType == 71) && ifc.FirstGatewayAddress != nil {
                if primaryInterface == nil || (ifc.Ipv4Metric < primaryInterface.Ipv4Metric) {
                    primaryInterface = ifc
                }
            }
        }
    }

    if primaryInterface == nil {
        return fmt.Errorf("unable to find a valid network interface")
    }

    base.Info("GetLocalInterface:", primaryInterface.AdapterName(), primaryInterface.Description(),
        primaryInterface.FriendlyName(), primaryInterface.Ipv4Metric, primaryInterface.IfType)

    base.LocalInterface.Name = primaryInterface.FriendlyName()
    base.LocalInterface.Ip4 = primaryInterface.FirstUnicastAddress.Address.IP().String()
    base.LocalInterface.Gateway = primaryInterface.FirstGatewayAddress.Address.IP().String()
    base.LocalInterface.Mac = net.HardwareAddr(primaryInterface.PhysicalAddress()).String()

    localInterface = primaryInterface.LUID

    return nil
}

func SetMTU(ifname string, mtu int) error {
    cmdStr := fmt.Sprintf("netsh interface ipv4 set subinterface \"%s\" MTU=%d", ifname, mtu)
    err := execCmd([]string{cmdStr})
    return err
}

func routingError(dst netip.Prefix, err error) error {
    return fmt.Errorf("routing error: %s %s", dst.String(), err)
}

func execCmd(cmdStrs []string) error {
    for _, cmdStr := range cmdStrs {
        cmd := exec.Command("cmd", "/C", cmdStr)
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

    var servers []netip.Addr
    for _, dns := range cSess.DNS {
        addr, _ := netip.ParseAddr(dns)
        servers = append(servers, addr)
    }

    err := iface.SetDNS(windows.AF_INET, servers, []string{})
    return err
}
