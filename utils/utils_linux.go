package utils

import (
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

func SetRoutes(ServerIP string, SplitInclude, SplitExclude *[]string) error {
    // routes
    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    gateway := net.ParseIP(base.LocalInterface.Gateway)

    ifaceIndex := iface.Attrs().Index
    localInterfaceIndex := localInterface.Attrs().Index

    route := netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway}
    err := netlink.RouteAdd(&route)
    if err != nil {
        return routingError(dst)
    }

    if len(*SplitInclude) == 0 {
        dst, _ = netlink.ParseIPNet("0.0.0.0/0")
        route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst}
        err = netlink.RouteAdd(&route)
        if err != nil {
            return routingError(dst)
        }
    } else {
        for _, ipMask := range *SplitInclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            route = netlink.Route{LinkIndex: ifaceIndex, Dst: dst, Priority: 6}
            err = netlink.RouteAdd(&route)
            if err != nil {
                return routingError(dst)
            }
        }
    }

    // 支持在 SplitInclude 网段中排除某个路由
    if len(*SplitExclude) > 0 {
        for _, ipMask := range *SplitExclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            route = netlink.Route{LinkIndex: localInterfaceIndex, Dst: dst, Gw: gateway, Priority: 5}
            err = netlink.RouteAdd(&route)
            if err != nil {
                return routingError(dst)
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

func routingError(dst *net.IPNet) error {
    return fmt.Errorf("routing error: %s", dst.String())
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
