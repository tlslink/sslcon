package utils

import (
    "fmt"
    "github.com/vishvananda/netlink"
    "net"
    "os"
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

        // OpenWrt 会将 127.0.0.1 写在最下面，影响其上面的解析
        os.Remove("/etc/resolv.conf")
        // time.Sleep(time.Millisecond)

        var dnsString string
        for _, dns := range DNS {
            dnsString += fmt.Sprintf("nameserver %s\n", dns)
        }
        NewRecord("/etc/resolv.conf").Prepend(dnsString)
    }

    return err
}

func SetRoutes(ServerIP string, SplitInclude, SplitExclude *[]string) error {
    // routes
    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    gateway := net.ParseIP(base.LocalInterface.Gateway)

    ifaceIndex := iface.Attrs().Index
    localInterfaceIndex := localInterface.Attrs().Index

    // 重置默认路由优先级，如 OpenWrt 默认优先级为 0
    zero, _ := netlink.ParseIPNet("0.0.0.0/0")
    _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero})
    _ = netlink.RouteAdd(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero, Gw: gateway, Priority: 10})

    route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
    err := netlink.RouteAdd(&route)
    if err != nil {
        return routingError(dst, err)
    }

    if len(*SplitInclude) == 0 {
        *SplitInclude = append(*SplitInclude, "0.0.0.0/0.0.0.0")
    }
    for _, ipMask := range *SplitInclude {
        dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
        route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 6}
        err = netlink.RouteAdd(&route)
        if err != nil {
            return routingError(dst, err)
        }
    }

    // 支持在 SplitInclude 网段中排除某个路由
    if len(*SplitExclude) > 0 {
        for _, ipMask := range *SplitExclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            route = netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway, Priority: 5}
            err = netlink.RouteAdd(&route)
            if err != nil {
                return routingError(dst, err)
            }
        }
    }

    return err
}

func ResetRoutes(ServerIP string, DNS, SplitExclude []string) {
    // routes
    localInterfaceIndex := localInterface.Attrs().Index

    // 重置默认路由优先级
    zero, _ := netlink.ParseIPNet("0.0.0.0/0")
    gateway := net.ParseIP(base.LocalInterface.Gateway)
    _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero})
    _ = netlink.RouteAdd(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: zero, Gw: gateway, Priority: 0})

    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})

    if len(SplitExclude) > 0 {
        for _, ipMask := range SplitExclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst})
        }
    }

    // dns
    // 软件崩溃会导致无法恢复 resolv.conf 从而无法上网，需要重启系统
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

func routingError(dst *net.IPNet, err error) error {
    return fmt.Errorf("routing error: %s %s", dst.String(), err)
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
