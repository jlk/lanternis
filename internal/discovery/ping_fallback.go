//go:build !integration

package discovery

import (
	"context"
	"net"
	"time"
)

func pingHost(ctx context.Context, ip string) bool {
	_ = ctx
	// Default (non-integration) build: TCP connect probe (80/443) as a weak reachability hint.
	// Real ICMP echo lives behind the `integration` build tag.
	for _, port := range []string{"80", "443"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

