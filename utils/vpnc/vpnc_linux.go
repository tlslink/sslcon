package vpnc

import (
    "fmt"
    "github.com/vishvananda/netlink"
    "net"
    "os/exec"
    "sslcon/base"
    "sslcon/session"
    "sslcon/utils"
    "strings"
    "time"
)

var (
    localInterface netlink.Link
    iface          netlink.Link
)

func ConfigInterface(cSess *session.ConnSession) error {
    var err error
    iface, err = netlink.LinkByName(cSess.TunName)
    if err != nil {
        return err
    }
    // ip address
    _ = netlink.LinkSetUp(iface)
    _ = netlink.LinkSetMulticastOff(iface)

    addr, _ := netlink.ParseAddr(utils.IpMask2CIDR(cSess.VPNAddress, cSess.VPNMask))
    err = netlink.AddrAdd(iface, addr)

    return err
}

func SetRoutes(cSess *session.ConnSession) error {
    // routes
    dst, _ := netlink.ParseIPNet(cSess.ServerAddress + "/32")
    gateway := net.ParseIP(base.LocalInterface.Gateway)

    ifaceIndex := iface.Attrs().Index
    localInterfaceIndex := localInterface.Attrs().Index

    route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
    err := netlink.RouteAdd(&route)
    if err != nil {
        if !strings.HasSuffix(err.Error(), "exists") {
            return routingError(dst, err)
        }
    }

    // 如果包含路由为空必为全局路由，如果使用包含域名，则包含路由必须填写一个，如 dns 地址
    if len(cSess.SplitInclude) == 0 {
        cSess.SplitInclude = append(cSess.SplitInclude, "0.0.0.0/0.0.0.0")

        // 全局模式，重置默认路由优先级，如 OpenWrt 默认优先级为 0
        zero, _ := netlink.ParseIPNet("0.0.0.0/0")
        delAllRoute(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero})
        _ = netlink.RouteAdd(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero, Gw: gateway, Priority: 10})
    }

    // 如果使用域名包含，原则上不支持在顶级域名匹配中排除某个具体域名的 IP
    for _, ipMask := range cSess.SplitInclude {
        dst, _ = netlink.ParseIPNet(utils.IpMaskToCIDR(ipMask))
        route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 6}
        err = netlink.RouteAdd(&route)
        if err != nil {
            if !strings.HasSuffix(err.Error(), "exists") {
                return routingError(dst, err)
            }
        }
    }

    // 支持在 SplitInclude 网段中排除某个路由
    if len(cSess.SplitExclude) > 0 {
        for _, ipMask := range cSess.SplitExclude {
            dst, _ = netlink.ParseIPNet(utils.IpMaskToCIDR(ipMask))
            route = netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway, Priority: 5}
            err = netlink.RouteAdd(&route)
            if err != nil {
                if !strings.HasSuffix(err.Error(), "exists") {
                    return routingError(dst, err)
                }
            }
        }
    }

    if len(cSess.DNS) > 0 {
        setDNS(cSess)
    }

    return nil
}

func ResetRoutes(cSess *session.ConnSession) {
    // routes
    localInterfaceIndex := localInterface.Attrs().Index

    for _, ipMask := range cSess.SplitInclude {
        if ipMask == "0.0.0.0/0.0.0.0" {
            // 重置默认路由优先级
            zero, _ := netlink.ParseIPNet("0.0.0.0/0")
            gateway := net.ParseIP(base.LocalInterface.Gateway)
            _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero})
            _ = netlink.RouteAdd(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero, Gw: gateway})
            break
        }
    }

    dst, _ := netlink.ParseIPNet(cSess.ServerAddress + "/32")
    _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})

    if len(cSess.SplitExclude) > 0 {
        for _, ipMask := range cSess.SplitExclude {
            dst, _ = netlink.ParseIPNet(utils.IpMaskToCIDR(ipMask))
            _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})
        }
    }

    if len(cSess.DynamicSplitExcludeDomains) > 0 {
        cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
            ips := value.([]string)
            for _, ip := range ips {
                dst, _ = netlink.ParseIPNet(ip + "/32")
                _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})
            }

            return true
        })
    }

    if len(cSess.DNS) > 0 {
        restoreDNS(cSess)
    }
}

func DynamicAddIncludeRoutes(ips []string) {
    ifaceIndex := iface.Attrs().Index

    for _, ip := range ips {
        dst, _ := netlink.ParseIPNet(ip + "/32")
        route := netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 6}
        _ = netlink.RouteAdd(&route)
    }
}

func DynamicAddExcludeRoutes(ips []string) {
    localInterfaceIndex := localInterface.Attrs().Index
    gateway := net.ParseIP(base.LocalInterface.Gateway)

    for _, ip := range ips {
        dst, _ := netlink.ParseIPNet(ip + "/32")
        route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway, Priority: 5}
        _ = netlink.RouteAdd(&route)
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

        base.Info("GetLocalInterface:", fmt.Sprintf("%+v", *base.LocalInterface))
        return nil
    }
    return err
}

func delAllRoute(route *netlink.Route) {
    err := netlink.RouteDel(route)
    if err != nil {
        return
    }
    delAllRoute(route)
}

func routingError(dst *net.IPNet, err error) error {
    return fmt.Errorf("routing error: %s %s", dst.String(), err)
}

func setDNS(cSess *session.ConnSession) {
    // dns
    if len(cSess.DNS) > 0 {
        // 使用动态域名路由时 DNS 一定走 VPN 才能进行流量分析
        if len(cSess.DynamicSplitIncludeDomains) > 0 {
            DynamicAddIncludeRoutes(cSess.DNS)
        }

        // 部分云服务器会在设置路由时重写 /etc/resolv.conf，延迟两秒再设置
        go func() {
            utils.CopyFile("/tmp/resolv.conf.bak", "/etc/resolv.conf")

            var dnsString string
            for _, dns := range cSess.DNS {
                dnsString += fmt.Sprintf("nameserver %s\n", dns)
            }
            time.Sleep(2 * time.Second)
            // OpenWrt 会将 127.0.0.1 写在最下面，影响其上面的解析
            err := utils.NewRecord("/etc/resolv.conf").Write(dnsString, false)
            if err != nil {
                base.Error("set DNS failed")
            }
        }()
    }
}

func restoreDNS(cSess *session.ConnSession) {
    // dns
    // 软件崩溃会导致无法恢复 resolv.conf 从而无法上网，需要重启系统
    if len(cSess.DNS) > 0 {
        utils.CopyFile("/etc/resolv.conf", "/tmp/resolv.conf.bak")
    }
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
