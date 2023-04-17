package utils

import (
    "fmt"
    "github.com/vishvananda/netlink"
    "net"
    "os/exec"
    "vpnagent/base"
)

var localInterface netlink.Link

func ConfigInterface(TunName, VPNAddress, VPNMask, ServerIP string, DNS, SplitInclude, SplitExclude []string) error {
    iface, err := netlink.LinkByName(TunName)
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

    // routes
    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    route := netlink.Route{LinkIndex: localInterface.Attrs().Index, Dst: dst, Gw: net.ParseIP(base.LocalInterface.Gateway)}
    err = netlink.RouteAdd(&route)
    if err != nil {
        return err
    }

    if len(SplitInclude) == 0 {
        dst, _ = netlink.ParseIPNet("0.0.0.0/0")
        route = netlink.Route{LinkIndex: iface.Attrs().Index, Dst: dst, Priority: 5}
        err = netlink.RouteAdd(&route)
        if err != nil {
            return err
        }

        if len(SplitExclude) != 0 {
            for _, ipMask := range SplitExclude {
                dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
                route = netlink.Route{LinkIndex: localInterface.Attrs().Index, Dst: dst, Gw: net.ParseIP(base.LocalInterface.Gateway)}
                _ = netlink.RouteAdd(&route)
            }
        }
    } else {
        for _, ipMask := range SplitInclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            route = netlink.Route{LinkIndex: iface.Attrs().Index, Dst: dst}
            _ = netlink.RouteAdd(&route)
        }
    }

    // dns
    CopyFile("/tmp/resolv.conf.bak", "/etc/resolv.conf")
    var dnsString string
    for _, dns := range DNS {
        dnsString += fmt.Sprintf("nameserver %s\n", dns)
    }
    NewRecord("/etc/resolv.conf").Prepend(dnsString)

    return err
}

func ResetRouting(ServerIP string, DNS, SplitExclude []string) {
    // routes
    dst, _ := netlink.ParseIPNet(ServerIP + "/32")
    _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterface.Attrs().Index, Dst: dst})

    if len(SplitExclude) != 0 {
        for _, ipMask := range SplitExclude {
            dst, _ = netlink.ParseIPNet(IpMaskToCIDR(ipMask))
            _ = netlink.RouteDel(&netlink.Route{LinkIndex: localInterface.Attrs().Index, Dst: dst})
        }
    }

    // dns
    CopyFile("/etc/resolv.conf", "/tmp/resolv.conf.bak")
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
