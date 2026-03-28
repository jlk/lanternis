//go:build integration

package discovery

import "context"

func probeReachable(ctx context.Context, ip string, _ string) (bool, []string) {
	if icmpProbe(ctx, ip) {
		return true, []string{"icmp"}
	}
	return false, nil
}

// TCPProbeProfiles is nil when the integration build uses ICMP instead of TCP.
func TCPProbeProfiles() map[string][]string {
	return nil
}
