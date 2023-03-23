package utils

import (
    "golang.org/x/sys/windows"
    "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
    "net"
    "net/netip"
    "strings"
    "vpnagent/base"
    "vpnagent/tun"
)

func ConfigInterface(VPNAddress, VPNMask, ServerIP string, DNS, SplitInclude, SplitExclude []string) error {
    // tunName, err := tun.NativeTunDevice.Name()

    iface := winipcfg.LUID(tun.NativeTunDevice.LUID())
    // ip address
    prefixVPN, _ := netip.ParsePrefix(IpMask2CIDR(VPNAddress, VPNMask))
    err := iface.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{prefixVPN})
    if err != nil {
        return err
    }

    // routes
    targetDefault, _ := netip.ParsePrefix("0.0.0.0/0")
    addr, _ := netip.ParseAddr(VPNAddress)

    targetServer, _ := netip.ParsePrefix(ServerIP + "/32")
    gateway, _ := netip.ParseAddr(base.LocalInterface.Gateway)

    routes := []*winipcfg.RouteData{
        {targetDefault, addr, 6},
        {targetServer, gateway, 5}}
    err = iface.AddRoutes(routes)
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

func ResetRouting(ServerIP string, DNS, SplitExclude []string) {}

func GetLocalInterface() error {
    ifcs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways)
    if err != nil {
        return err
    }

    var primaryInterface *winipcfg.IPAdapterAddresses
    for _, ifc := range ifcs {
        println(ifc.AdapterName(), ifc.Description(), ifc.FriendlyName(), ifc.Ipv4Metric, ifc.IfType)
        // exclude Virtual Ethernet and Loopback Adapter
        if !strings.Contains(ifc.Description(), "Virtual") {
            // https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/types.go?h=v0.5.3#n61
            if ifc.IfType == 6 || ifc.IfType == 71 {
                if primaryInterface == nil || (ifc.FirstGatewayAddress != nil && ifc.Ipv4Metric < primaryInterface.Ipv4Metric) {
                    primaryInterface = ifc
                }
            }
        }
    }

    base.LocalInterface.Name = primaryInterface.FriendlyName()
    base.LocalInterface.Ip4 = primaryInterface.FirstUnicastAddress.Address.IP().String()
    base.LocalInterface.Gateway = primaryInterface.FirstGatewayAddress.Address.IP().String()
    base.LocalInterface.Mac = net.HardwareAddr(primaryInterface.PhysicalAddress()).String()
    return nil
}
