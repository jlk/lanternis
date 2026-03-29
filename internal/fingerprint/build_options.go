package fingerprint

import "github.com/jlk/lanternis/internal/discovery"

// BuildOptions configures optional fingerprint probes (TCP profile, etc.).
type BuildOptions struct {
	// TCPProfile is light | normal | thorough | deep (see discovery.NormalizeTCPProfile).
	// Deep enables raw SYN/SYN-ACK TCP fingerprinting on Linux (CAP_NET_RAW / root).
	TCPProfile string
}

func tcpProfileDeep(opts *BuildOptions) bool {
	if opts == nil {
		return false
	}
	return discovery.NormalizeTCPProfile(opts.TCPProfile) == discovery.TCPProfileDeep
}
