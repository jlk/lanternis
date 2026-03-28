package passive

import (
	"fmt"
	"net"
)

// LANBinding describes the local interface used for SSDP and mDNS on the scanned subnet.
type LANBinding struct {
	InterfaceName string
	LocalIP       string
}

// LANBindingForCIDR finds an up, non-loopback interface with an IPv4 address inside cidr.
// If none match (e.g. wrong CIDR vs this host), returns empty binding and nil error.
func LANBindingForCIDR(cidr string) (LANBinding, error) {
	ifi, ip, err := findLANMatch(cidr)
	if err != nil {
		return LANBinding{}, err
	}
	if ifi == nil || ip == nil {
		return LANBinding{}, nil
	}
	return LANBinding{InterfaceName: ifi.Name, LocalIP: ip.String()}, nil
}

func findLANMatch(cidr string) (*net.Interface, net.IP, error) {
	_, targetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cidr: %w", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range ifaces {
		ifi := &ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && targetNet.Contains(ip4) {
				return ifi, append(net.IP(nil), ip4...), nil
			}
		}
	}
	return nil, nil, nil
}

func interfaceForCIDR(cidr string) (*net.Interface, error) {
	ifi, _, err := findLANMatch(cidr)
	return ifi, err
}
