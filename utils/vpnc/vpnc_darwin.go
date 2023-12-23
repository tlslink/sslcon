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

func ConfigInterface(cSess *session.ConnSession) error {
	cmdStr1 := fmt.Sprintf("ifconfig %s inet %s %s netmask %s up", cSess.TunName, cSess.VPNAddress, cSess.VPNAddress, "255.255.255.255")
	err := execCmd([]string{cmdStr1})
	if err != nil {
		return err
	}

	// dns
	err = setDNS(cSess)

	return err
}

func SetRoutes(cSess *session.ConnSession) error {
	cmdStr1 := fmt.Sprintf("route add -host %s %s", cSess.ServerAddress, base.LocalInterface.Gateway)
	err := execCmd([]string{cmdStr1})
	if err != nil {
		return err
	}

	if len(cSess.SplitInclude) == 0 {
		cmdStr2 := fmt.Sprintf("route delete default %s", base.LocalInterface.Gateway)
		cmdStr3 := fmt.Sprintf("route add default %s", cSess.VPNAddress)
		err = execCmd([]string{cmdStr2, cmdStr3})
		if err != nil {
			return err
		}
	} else {
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

	return nil
}

func ResetRoutes(cSess *session.ConnSession) {
	cmdStr1 := fmt.Sprintf("route delete default %s", cSess.VPNAddress)
	cmdStr2 := fmt.Sprintf("route add default %s", base.LocalInterface.Gateway)

	cmdStr3 := fmt.Sprintf("route delete -host %s %s", cSess.ServerAddress, base.LocalInterface.Gateway)
	_ = execCmd([]string{cmdStr1, cmdStr2, cmdStr3})

	if len(cSess.SplitExclude) > 0 {
		for _, ipMask := range cSess.SplitExclude {
			dst := utils.IpMaskToCIDR(ipMask)
			cmdStr := fmt.Sprintf("route delete -net %s %s", dst, base.LocalInterface.Gateway)
			_ = execCmd([]string{cmdStr})
		}
	}

	restoreDNS(cSess)
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
	command := fmt.Sprintf(`
		open
		d.init
		d.add ServerAddresses * %s
		set State:/Network/Service/%s/DNS
		d.init
		d.add Router %s
		d.add Addresses * %s
		d.add SubnetMasks * 255.255.255.255
		d.add InterfaceName %s
		d.add OverridePrimary # 1
		set State:/Network/Service/%s/IPv4
		close
	`, strings.Join(cSess.DNS, " "), cSess.TunName, cSess.VPNAddress, cSess.VPNAddress, cSess.TunName, cSess.TunName)

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
