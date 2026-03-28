//go:build !integration

package discovery

func ProbeMode() string {
	return "tcp_fallback"
}

func ProbeGuidance() string {
	return "Using TCP fallback probe. For real ICMP echo, run with -tags=integration (and required OS permissions)."
}

