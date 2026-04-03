package nmapenrich

import (
	"strconv"
	"strings"
)

const maxTCPPortsPerScan = 24

// BuildPortSpec returns TCP port numbers and whether to probe UDP 1900 for SSDP-related NSE.
func BuildPortSpec(openPorts []string, hints map[string]any) (tcp []string, udp1900 bool) {
	seen := make(map[string]struct{})
	for _, p := range openPorts {
		p = strings.TrimSpace(p)
		if p == "" || strings.EqualFold(p, "icmp") {
			continue
		}
		if _, err := strconv.Atoi(p); err != nil {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		tcp = append(tcp, p)
	}
	if len(tcp) > maxTCPPortsPerScan {
		tcp = tcp[:maxTCPPortsPerScan]
	}
	if hints == nil {
		return tcp, false
	}
	ssdp, ok := hints["ssdp"].(map[string]any)
	if !ok {
		return tcp, false
	}
	if loc, ok := ssdp["location"].(string); ok && strings.TrimSpace(loc) != "" {
		udp1900 = true
		return tcp, udp1900
	}
	if st, ok := ssdp["st_types"].([]any); ok && len(st) > 0 {
		udp1900 = true
		return tcp, udp1900
	}
	if st, ok := ssdp["st_types"].([]string); ok && len(st) > 0 {
		udp1900 = true
	}
	return tcp, udp1900
}
