package utils

import (
    "context"
    "fmt"
    "github.com/vishvananda/netlink"
    "net"
    "os/exec"
    "vpnagent/base"
)

var (
    localInterface netlink.Link
    iface          netlink.Link
)

func ConfigInterface(TunName, VPNAddress, VPNMask string, DNS []string) error {
    var err error
    iface, err = netlink.LinkByName(TunName)
    if err != nil {
        return err
    }
    // ip address
    _ = netlink.LinkSetUp(iface)
    _ = netlink.LinkSetMulticastOff(iface)

    addr, _ := netlink.ParseAddr(IpMask2CIDR(VPNAddress, VPNMask))
    err = netlink.AddrAdd(iface, addr)
    if err != nil {
        return err
    }

    // dns
    if len(DNS) > 0 {
        CopyFile("/tmp/resolv.conf.bak", "/etc/resolv.conf")
        var dnsString string
        for _, dns := range DNS {
            dnsString += fmt.Sprintf("nameserver %s\n", dns)
        }
        NewRecord("/etc/resolv.conf").Prepend(dnsString)
        // time.Sleep(time.Duration(6) * time.Second)
    }

    return err
}

func SetRoutes(ServerIP string, SplitInclude, SplitExclude, DynamicSplitIncludeDomains, DynamicSplitExcludeDomains *[]string) error {
    // routes
    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    gateway := net.ParseIP(base.LocalInterface.Gateway)

    ifaceIndex := iface.Attrs().Index
    localInterfaceIndex := localInterface.Attrs().Index

    // 为了方便，无论 Include 还是 Exclude 都添加，其实 Include 不需要
    route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
    err := netlink.RouteAdd(&route)
    if err != nil {
        return err
    }

    // anylink 包含路由默认为 all，下发的 SplitInclude 实际为 nil
    // 不支持包含路由手动填为 0.0.0.0/0 的情况
    // 包含域名只能和包含路由搭配使用，排除域名只能和排除路由搭配使用
    // Go 网络库每隔5秒读取 /etc/resolv.conf，设置 dns 后立即解析域名是否会使用设置的 dns 有待确认
    if len(*SplitInclude) > 0 || len(*DynamicSplitIncludeDomains) > 0 {
        if len(*SplitInclude) > 0 {
            for _, ipMask := range *SplitInclude {
                dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
                route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst}
                _ = netlink.RouteAdd(&route)
            }
        }

        if len(*DynamicSplitIncludeDomains) > 0 {
            // -tags 'netcgo'，也无法应对一个域名对应多个 ip 的情况
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
                                dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
                                route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst}
                                _ = netlink.RouteAdd(&route)

                                *SplitInclude = append(*SplitInclude, ipMask)
                            }
                        }
                    }
                }
            }
        }
    } else {
        dst, _ = netlink.ParseIPNet("0.0.0.0/0")
        route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 5}
        err = netlink.RouteAdd(&route)
        if err != nil {
            return err
        }

        if len(*SplitExclude) > 0 {
            for _, ipMask := range *SplitExclude {
                dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
                route = netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
                _ = netlink.RouteAdd(&route)
            }
        }

        if len(*DynamicSplitExcludeDomains) > 0 {
            // -tags 'netcgo'
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
                                dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
                                route = netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
                                _ = netlink.RouteAdd(&route)

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
    // routes
    localInterfaceIndex := localInterface.Attrs().Index
    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})

    if len(SplitExclude) > 0 {
        for _, ipMask := range SplitExclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})
        }
    }

    // dns
    if len(DNS) > 0 {
        CopyFile("/etc/resolv.conf", "/tmp/resolv.conf.bak")
    }
}

func GetLocalInterface() error {

    // just for default route
    routes, err := netlink.RouteGet(net.ParseIP("8.8.8.8"))
    if len(routes) > 0 {
        route := routes[0]
        localInterface, err = netlink.LinkByIndex(route.LinkIndex)
        if err != nil {
            return err
        }
        base.LocalInterface.Name = localInterface.Attrs().Name
        base.LocalInterface.Ip4 = route.Src.String()
        base.LocalInterface.Gateway = route.Gw.String()
        base.LocalInterface.Mac = localInterface.Attrs().HardwareAddr.String()

        base.Info("GetLocalInterface: ", *base.LocalInterface)
        return nil
    }
    return err
}

func execCmd(cmdStrs []string) error {
    for _, cmdStr := range cmdStrs {
        cmd := exec.Command("sh", "-c", cmdStr)
        b, err := cmd.CombinedOutput()
        if err != nil {
            return fmt.Errorf("%s %s", string(b), cmd.String())
        }
    }
    return nil
}
