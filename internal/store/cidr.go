package store

import "net"

// ipInCIDR reports whether ipStr is contained in cidr (IPv4). Duplicated from
// discovery/passive to avoid an import cycle (passive applies store updates).
func ipInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}
