//go:build !integration

package discovery

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Curated TCP targets: web and common consumer IoT / NAS / automation (TCP only).
var (
	tcpPortsLight = []string{"80", "443", "8080"}

	tcpPortsNormalExtra = []string{
		"8443", "554", "5000", "8888",
	}

	// Extra ports for thorough: remote admin, file share, MQTT, printing, HomeKit, discovery, media, HA.
	tcpPortsThoroughExtra = []string{
		"22", "23", "139", "445",
		"1883", "8883",
		"9100",
		"62078",
		"5357", "7680",
		"32400", "8123",
	}
)

// PortsForTCPProfile returns the port list for a profile (immutable copy).
func PortsForTCPProfile(profile string) []string {
	switch NormalizeTCPProfile(profile) {
	case TCPProfileLight:
		return append([]string(nil), tcpPortsLight...)
	case TCPProfileThorough:
		out := append(append(append([]string{}, tcpPortsLight...), tcpPortsNormalExtra...), tcpPortsThoroughExtra...)
		return dedupeStringsStable(out)
	default:
		return append(append([]string{}, tcpPortsLight...), tcpPortsNormalExtra...)
	}
}

func dedupeStringsStable(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func budgetForTCPProfile(profile string) time.Duration {
	switch NormalizeTCPProfile(profile) {
	case TCPProfileLight:
		return 260 * time.Millisecond
	case TCPProfileThorough:
		return 480 * time.Millisecond
	default:
		return 340 * time.Millisecond
	}
}

// tcpReachable tries TCP connects in parallel and returns every port that accepted within the budget.
func tcpReachable(ctx context.Context, ip string, profile string) (bool, []string) {
	ports := PortsForTCPProfile(profile)
	if len(ports) == 0 {
		return false, nil
	}
	return tcpReachableWithPorts(ctx, ip, ports, budgetForTCPProfile(profile))
}

// tcpReachableWithPorts dials all listed ports in parallel and collects successes until the budget elapses.
func tcpReachableWithPorts(ctx context.Context, ip string, ports []string, budget time.Duration) (bool, []string) {
	if len(ports) == 0 {
		return false, nil
	}
	ctx2, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var mu sync.Mutex
	open := make([]string, 0, len(ports))
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			var d net.Dialer
			conn, err := d.DialContext(ctx2, "tcp", net.JoinHostPort(ip, p))
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	if len(open) == 0 {
		return false, nil
	}
	sortPortsNumeric(open)
	return true, open
}

func sortPortsNumeric(ports []string) {
	sort.Slice(ports, func(i, j int) bool {
		a, ea := strconv.Atoi(ports[i])
		b, eb := strconv.Atoi(ports[j])
		if ea != nil || eb != nil {
			return ports[i] < ports[j]
		}
		return a < b
	})
}

func probeReachable(ctx context.Context, ip string, profile string) (reachable bool, openPorts []string) {
	return tcpReachable(ctx, ip, profile)
}

// TCPProbeProfiles lists ports per profile for /api/diagnostics (default build only).
func TCPProbeProfiles() map[string][]string {
	return map[string][]string{
		TCPProfileLight:    PortsForTCPProfile(TCPProfileLight),
		TCPProfileNormal:   PortsForTCPProfile(TCPProfileNormal),
		TCPProfileThorough: PortsForTCPProfile(TCPProfileThorough),
	}
}
