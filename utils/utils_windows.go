package utils

import (
    "context"
    "fmt"
    "golang.org/x/sys/windows"
    "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
    "net"
    "net/netip"
    "os/exec"
    "strings"
    "vpnagent/base"
    "vpnagent/tun"
)

var (
    localInterface winipcfg.LUID
    iface          winipcfg.LUID
    nextHopVPN     netip.Addr
)

func ConfigInterface(TunName, VPNAddress, VPNMask string, DNS []string) error {
    mtu, _ := tun.NativeTunDevice.MTU()
    err := SetMTU(TunName, mtu)
    if err != nil {
        return err
    }

    iface = winipcfg.LUID(tun.NativeTunDevice.LUID())

    // ip address
    iface.FlushIPAddresses(windows.AF_UNSPEC)

    nextHopVPN, _ = netip.ParseAddr(VPNAddress)
    prefixVPN, _ := netip.ParsePrefix(IpMask2CIDR(VPNAddress, VPNMask))
    err = iface.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{prefixVPN})
    if err != nil {
        return err
    }

    // dns
    var servers []netip.Addr
    for _, dns := range DNS {
        addr, _ := netip.ParseAddr(dns)
        servers = append(servers, addr)
    }

    err = iface.SetDNS(windows.AF_INET, servers, []string{})
    if err != nil {
        return err
    }

    return nil
}

func SetRoutes(ServerIP string, SplitInclude, SplitExclude, DynamicSplitIncludeDomains, DynamicSplitExcludeDomains *[]string) error {
    // routes
    targetServer, err := netip.ParsePrefix(ServerIP + "/32")
    nextHopVPNGateway, _ := netip.ParseAddr(base.LocalInterface.Gateway)
    localInterface.AddRoute(targetServer, nextHopVPNGateway, 6)

    if len(*SplitInclude) > 0 || len(*DynamicSplitIncludeDomains) > 0 {
        if len(*SplitInclude) > 0 {
            routes := []*winipcfg.RouteData{}
            for _, ipMask := range *SplitInclude {
                dst, _ := netip.ParsePrefix(IpMaskToCIDR(ipMask))
                routes = append(routes, &winipcfg.RouteData{dst, nextHopVPN, 5})
            }
            iface.AddRoutes(routes)
        }
        if len(*DynamicSplitIncludeDomains) > 0 {
            resolver := &net.Resolver{}
            for _, domain := range *DynamicSplitIncludeDomains {
                if domain != "" {
                    // 尝试解决一个域名对应多个 IP 地址情况，不太靠谱
                    cname, _ := resolver.LookupCNAME(context.Background(), domain)
                    if cname != "" && domain+"." != cname {
                        domain = cname
                        // 最多两层套娃，www.baidu.com > www.a.shifen.com > www.wshifen.com
                        cname2, _ := resolver.LookupCNAME(context.Background(), domain)
                        if cname2 != "" && domain != cname2 {
                            domain = cname2
                        }
                    }
                    ips, _ := resolver.LookupIP(context.Background(), "ip4", domain)
                    if len(ips) > 0 {
                        for _, ip := range ips {
                            if ip != nil {
                                ipMask := ip.String() + "/255.255.255.255"
                                dst, _ := netip.ParsePrefix(IpMaskToCIDR(ipMask))
                                iface.AddRoute(dst, nextHopVPN, 5)

                                *SplitInclude = append(*SplitInclude, ipMask)
                            }
                        }
                    }
                }
            }
        }
    } else {
        targetDefault, _ := netip.ParsePrefix("0.0.0.0/0")
        err = iface.AddRoute(targetDefault, nextHopVPN, 5)
        if err != nil {
            return err
        }
        if len(*SplitExclude) > 0 {
            routes := []*winipcfg.RouteData{}
            for _, ipMask := range *SplitExclude {
                dst, _ := netip.ParsePrefix(IpMaskToCIDR(ipMask))
                routes = append(routes, &winipcfg.RouteData{dst, nextHopVPNGateway, 6})
            }
            localInterface.AddRoutes(routes)
        }

        if len(*DynamicSplitExcludeDomains) > 0 {
            resolver := &net.Resolver{}
            for _, domain := range *DynamicSplitExcludeDomains {
                if domain != "" {
                    cname, _ := resolver.LookupCNAME(context.Background(), domain)
                    if cname != "" && domain+"." != cname {
                        domain = cname
                        // 最多两层套娃，www.baidu.com > www.a.shifen.com > www.wshifen.com
                        cname2, _ := resolver.LookupCNAME(context.Background(), domain)
                        if cname2 != "" && domain != cname2 {
                            domain = cname2
                        }
                    }
                    ips, _ := resolver.LookupIP(context.Background(), "ip4", domain)
                    if len(ips) > 0 {
                        for _, ip := range ips {
                            if ip != nil {
                                ipMask := ip.String() + "/255.255.255.255"
                                dst, _ := netip.ParsePrefix(IpMaskToCIDR(ipMask))
                                localInterface.AddRoute(dst, nextHopVPNGateway, 5)

                                *SplitExclude = append(*SplitExclude, ipMask)
                            }
                        }
                    }
                }
            }
        }
    }
    return err
}

func ResetRoutes(ServerIP string, DNS, SplitExclude []string) {
    targetServer, _ := netip.ParsePrefix(ServerIP + "/32")
    nextHopVPNGateway, _ := netip.ParseAddr(base.LocalInterface.Gateway)
    localInterface.DeleteRoute(targetServer, nextHopVPNGateway)

    if len(SplitExclude) > 0 {
        for _, ipMask := range SplitExclude {
            dst, _ := netip.ParsePrefix(IpMaskToCIDR(ipMask))
            localInterface.DeleteRoute(dst, nextHopVPNGateway)
        }
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

    base.Info("GetLocalInterface: ", primaryInterface.AdapterName(), primaryInterface.Description(),
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

func execCmd(cmdStrs []string) error {
    for _, cmdStr := range cmdStrs {
        cmd := exec.Command("cmd", "/C", cmdStr)
        b, err := cmd.CombinedOutput()
        if err != nil {
            return fmt.Errorf("%s %s", string(b), cmd.String())
        }
    }
    return nil
}
