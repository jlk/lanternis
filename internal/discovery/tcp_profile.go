package discovery

import "strings"

// TCP profile names align with scan UI modes (light / normal / thorough).
const (
	TCPProfileLight    = "light"
	TCPProfileNormal   = "normal"
	TCPProfileThorough = "thorough"
	// TCPProfileDeep is explicit consent: same port breadth as thorough, longer probes, raw TCP stack fingerprint (Linux).
	TCPProfileDeep = "deep"
)

// NormalizeTCPProfile maps UI/JSON values to light | normal | thorough | deep.
func NormalizeTCPProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case TCPProfileLight, "lite":
		return TCPProfileLight
	case TCPProfileThorough:
		return TCPProfileThorough
	case TCPProfileDeep:
		return TCPProfileDeep
	case "", TCPProfileNormal:
		return TCPProfileNormal
	default:
		return TCPProfileNormal
	}
}
