//go:build !integration

package discovery

func ProbeMode() string {
	return "tcp_fallback"
}

func ProbeGuidance() string {
	return "Using TCP connect probes; scan mode (light/normal/thorough) selects parallel host workers and port list (see tcp_probe_profiles in diagnostics). For ICMP echo, run with -tags=integration (and required OS permissions)."
}
