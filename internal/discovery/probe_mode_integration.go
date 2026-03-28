//go:build integration

package discovery

func ProbeMode() string {
	return "icmp_echo"
}

func ProbeGuidance() string {
	return "Using ICMP echo probe (integration build). Root/CAP_NET_RAW may be required depending on OS."
}

