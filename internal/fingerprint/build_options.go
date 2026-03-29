package fingerprint

import "github.com/jlk/lanternis/internal/discovery"

// BuildOptions configures optional fingerprint probes (TCP profile, etc.).
type BuildOptions struct {
	// TCPProfile is light | normal | thorough | deep (see discovery.NormalizeTCPProfile).
	// Deep enables raw SYN/SYN-ACK TCP fingerprinting on Linux (CAP_NET_RAW / root).
	TCPProfile string

	// DeviceAliases optional user rules (hostname substrings, MAC prefixes); nil skips user matching.
	DeviceAliases *DeviceAliasesFile
}

func tcpProfileDeep(opts *BuildOptions) bool {
	if opts == nil {
		return false
	}
	return discovery.NormalizeTCPProfile(opts.TCPProfile) == discovery.TCPProfileDeep
}

func optsDeviceAliases(opts *BuildOptions) *DeviceAliasesFile {
	if opts == nil {
		return nil
	}
	return opts.DeviceAliases
}

// httpExtraPathsEnabled is true for thorough/deep: extra capped GETs to curated paths (/version, /api/status).
func httpExtraPathsEnabled(opts *BuildOptions) bool {
	if opts == nil {
		return false
	}
	p := discovery.NormalizeTCPProfile(opts.TCPProfile)
	return p == discovery.TCPProfileThorough || p == discovery.TCPProfileDeep
}
