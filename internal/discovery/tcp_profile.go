package discovery

import "strings"

// TCP profile names align with scan UI modes (light / normal / thorough).
const (
	TCPProfileLight    = "light"
	TCPProfileNormal   = "normal"
	TCPProfileThorough = "thorough"
)

// NormalizeTCPProfile maps UI/JSON values to light | normal | thorough.
func NormalizeTCPProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case TCPProfileLight, "lite":
		return TCPProfileLight
	case TCPProfileThorough:
		return TCPProfileThorough
	case "", TCPProfileNormal:
		return TCPProfileNormal
	default:
		return TCPProfileNormal
	}
}
