package utils

import (
    "dtlslink/base"
    "errors"
    "fmt"
    "net"
    "os/exec"
    "strings"
)

func ConfigInterface(TunName, VPNAddress, VPNMask, ServerIP string, MTU int, DNS, SplitInclude, SplitExclude []string) error {
    // base.Debug(*base.LocalInterface)
    cmdStr1 := fmt.Sprintf("ip link set dev %s up mtu %d multicast off", TunName, MTU)
    cmdStr2 := fmt.Sprintf("ip addr add dev %s %s", TunName, IpMask2CIDR(VPNAddress, VPNMask))

    cmdStr3 := fmt.Sprintf("ip route add default dev %s", TunName)
    cmdStr4 := fmt.Sprintf("ip route add %s/32 via %s dev %s", ServerIP, base.LocalInterface.Gateway, base.LocalInterface.Name)

    err := execCmd([]string{cmdStr1, cmdStr2, cmdStr3, cmdStr4})
    if err != nil {
        return err
    }

    if len(SplitInclude) != 0 {
        for _, ipMask := range SplitInclude {
            cmdStr := fmt.Sprintf("ip route add %s dev %s", IpMaskToCIDR(ipMask), TunName)
            _ = execCmd([]string{cmdStr})
        }
    } else if len(SplitExclude) != 0 {
        for _, ipMask := range SplitExclude {
            cmdStr := fmt.Sprintf("ip route add %s via %s dev %s", IpMaskToCIDR(ipMask), base.LocalInterface.Gateway, base.LocalInterface.Name)
            _ = execCmd([]string{cmdStr})
        }
    }

    // todo: backup and restore dns?
    for _, dns := range DNS {
        // do not secure dns
        //dnsStr1 := fmt.Sprintf("ip route add %s/32 via %s dev %s", dns, base.LocalInterface.Gateway, base.LocalInterface.Name)
        //_ = execCmd([]string{dnsStr1})

        dnsStr2 := fmt.Sprintf("sed -i '1i\\nameserver %s'  /etc/resolv.conf", dns)
        err = execCmd([]string{dnsStr2})
    }

    return err
}

func ResetRouting(ServerIP string, DNS, SplitExclude []string) {
    cmdStr := fmt.Sprintf("ip route del %s/32 dev %s", ServerIP, base.LocalInterface.Name)
    _ = execCmd([]string{cmdStr})

    //for _, dns := range DNS {
    //    dnsStr1 := fmt.Sprintf("ip route del %s/32 via %s dev %s", dns, base.LocalInterface.Gateway, base.LocalInterface.Name)
    //    _ = execCmd([]string{dnsStr1})
    //}

    size := len(DNS)
    if size == 1 {
        _ = execCmd([]string{"sed -i '1d' /etc/resolv.conf"})
    } else if size > 1 {
        _ = execCmd([]string{fmt.Sprintf("sed -i '1,%dd' /etc/resolv.conf", size)})
    }
    if len(SplitExclude) != 0 {
        for _, ipMask := range SplitExclude {
            routeCmdStr := fmt.Sprintf("ip route del %s via %s dev %s", IpMaskToCIDR(ipMask), base.LocalInterface.Gateway, base.LocalInterface.Name)
            _ = execCmd([]string{routeCmdStr})
        }
    }
}

func GetLocalInterface() error {
    iface, err := getPrimaryInterface()
    if err != nil {
        return err
    }
    addrs, _ := iface.Addrs()
    var ip net.IP
    for _, addr := range addrs {
        switch v := addr.(type) {
        case *net.IPNet:
            ip = v.IP
        case *net.IPAddr:
            ip = v.IP
        }
        ip = ip.To4()
        if ip != nil {
            break
        }
    }

    base.LocalInterface.Name = iface.Name
    base.LocalInterface.Ip4 = ip.String()
    base.LocalInterface.Gateway = getDefaultGateway(iface.Name)
    base.LocalInterface.Mac = iface.HardwareAddr.String()

    return nil
}

func getPrimaryInterface() (net.Interface, error) {
    ifaces, _ := net.Interfaces()
    for _, iface := range ifaces {
        name := strings.ToLower(iface.Name)
        if strings.HasPrefix(name, "cscotun") {
            return net.Interface{}, errors.New("looks like there are other VPN services running")
        }
    }
    for _, iface := range ifaces {
        addrs, _ := iface.Addrs()
        if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp == 1 && len(addrs) != 0 {
            name := strings.ToLower(iface.Name)
            if strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "wl") {
                return iface, nil
            }
        }
    }
    return net.Interface{}, errors.New("failed to get a valid network interface")
}

func getDefaultGateway(iface string) string {
    cmd := exec.Command("sh", "-c", fmt.Sprintf("ip route show default dev %s", iface))
    b, err := cmd.CombinedOutput()
    if err != nil {
        base.Error(fmt.Errorf("%s %s", string(b), cmd.String()))
        return ""
    }
    route := strings.Split(strings.Split(string(b), "\n")[0], " ")
    for i, str := range route {
        if str == "via" {
            return route[i+1]
        }
    }
    return ""
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
