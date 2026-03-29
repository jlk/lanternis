package fingerprint

import (
	"net"
	"strings"
	"unicode/utf8"
)

const maxDisplayLabelRunes = 80

// DisplayLabel chooses a concise inventory label after fingerprinting. It prefers the
// structured summary (manufacturer/model, etc.), then host-like evidence (mDNS names,
// PTR, UPnP friendlyName), then hints-only fallbacks, then address.
func DisplayLabel(rec *Record, hints map[string]any, ip string) string {
	if rec == nil {
		return trimLabel(fallbackHintOnlyLabel(hints, ip))
	}
	if s := strings.TrimSpace(summarize(rec)); s != "" && !labelLooksLikeIP(s, ip) {
		return trimLabel(s)
	}
	if s := networkIdentityLabel(rec, hints, ip); s != "" {
		return trimLabel(s)
	}
	return trimLabel(firstNonEmpty(ip, fallbackHintOnlyLabel(hints, ip)))
}

func networkIdentityLabel(rec *Record, hints map[string]any, ip string) string {
	if s := firstSignal(rec, "mdns_name"); s != "" {
		if t := cleanHostishLabel(s, ip); t != "" {
			return t
		}
	}
	if s := firstSignal(rec, "ptr"); s != "" {
		if t := cleanPTRLabel(s, ip); t != "" {
			return t
		}
	}
	for _, sig := range rec.Signals {
		if sig.Source == "upnp_xml" && strings.EqualFold(sig.Field, "friendlyName") && strings.TrimSpace(sig.Value) != "" {
			return strings.TrimSpace(sig.Value)
		}
	}
	if s := friendlyNameFromMDNSServices(hints, ip); s != "" {
		return s
	}
	if s := bestMDNSNameFromHints(hints, ip); s != "" {
		return s
	}
	if s := strings.TrimSpace(rec.DeviceClass); s != "" {
		return s
	}
	if v := VendorFromRecord(rec); v != "" {
		return v
	}
	if s := firstSignal(rec, "http_title"); s != "" {
		return strings.TrimSpace(s)
	}
	if s := firstSignal(rec, "tls_cert"); s != "" {
		return strings.TrimSpace(s)
	}
	if s := firstSignal(rec, "ssh_banner"); s != "" {
		return strings.TrimSpace(s)
	}
	if s := firstSignal(rec, "oui"); s != "" {
		return strings.TrimSpace("NIC: " + s)
	}
	return ""
}

func firstSignal(rec *Record, source string) string {
	for _, s := range rec.Signals {
		if s.Source == source && strings.TrimSpace(s.Value) != "" {
			return strings.TrimSpace(s.Value)
		}
	}
	return ""
}

func friendlyNameFromMDNSServices(hints map[string]any, ip string) string {
	mdns, ok := hints["mdns"].(map[string]any)
	if !ok {
		return ""
	}
	raw, ok := mdns["services"].([]any)
	if !ok || len(raw) == 0 {
		return ""
	}
	for _, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"fn", "name", "friendly"} {
			if s := txtValue(m, k); s != "" {
				if t := cleanHostishLabel(s, ip); t != "" {
					return t
				}
			}
		}
		if inst, ok := m["instance"].(string); ok {
			if t := cleanMDNSInstance(inst, ip); t != "" {
				return t
			}
		}
		txt := stringSliceFromAny(m["txt"])
		for _, pair := range txt {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)
			switch k {
			case "fn", "name", "friendly":
				if t := cleanHostishLabel(v, ip); t != "" {
					return t
				}
			}
		}
	}
	return ""
}

func txtValue(m map[string]any, key string) string {
	want := strings.ToLower(strings.TrimSpace(key))
	for _, pair := range stringSliceFromAny(m["txt"]) {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if strings.ToLower(strings.TrimSpace(k)) == want {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func bestMDNSNameFromHints(hints map[string]any, ip string) string {
	mdns, ok := hints["mdns"].(map[string]any)
	if !ok {
		return ""
	}
	names := stringSliceFromAny(mdns["names"])
	if len(names) == 0 {
		return ""
	}
	best := ""
	bestScore := -1
	for _, n := range names {
		t := cleanHostishLabel(n, ip)
		if t == "" {
			continue
		}
		score := mdnsNameScore(t)
		if score > bestScore {
			bestScore = score
			best = t
		}
	}
	return best
}

func mdnsNameScore(s string) int {
	if len(s) < 3 {
		return 0
	}
	score := 20
	if strings.Contains(s, " ") {
		score -= 1
	}
	// Prefer readable tokens over opaque hex-ish blobs.
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits >= len(s)/2 && len(s) > 12 {
		score -= 12
	}
	// Small penalty for extremely long labels.
	if utf8.RuneCountInString(s) > 40 {
		score -= 4
	}
	return score
}

func fallbackHintOnlyLabel(hints map[string]any, ip string) string {
	if s := friendlyNameFromMDNSServices(hints, ip); s != "" {
		return s
	}
	if s := bestMDNSNameFromHints(hints, ip); s != "" {
		return s
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func trimLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	rs := []rune(s)
	if len(rs) > maxDisplayLabelRunes {
		s = string(rs[:maxDisplayLabelRunes]) + "…"
	}
	return s
}

func labelLooksLikeIP(s, ip string) bool {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, ip) {
		return true
	}
	if net.ParseIP(s) != nil && ip != "" && net.ParseIP(ip) != nil {
		return strings.EqualFold(strings.TrimSuffix(s, "."), strings.TrimSuffix(ip, "."))
	}
	return false
}

func cleanHostishLabel(s, ip string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	if strings.HasSuffix(low, ".local") {
		s = s[:len(s)-len(".local")]
		s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	}
	if labelLooksLikeIP(s, ip) {
		return ""
	}
	return strings.TrimSpace(s)
}

func cleanMDNSInstance(inst string, ip string) string {
	inst = strings.ReplaceAll(inst, "\x20", " ")
	inst = strings.TrimSpace(inst)
	if inst == "" {
		return ""
	}
	return cleanHostishLabel(inst, ip)
}

func cleanPTRLabel(ptr string, ip string) string {
	ptr = strings.TrimSpace(strings.TrimSuffix(ptr, "."))
	if ptr == "" {
		return ""
	}
	low := strings.ToLower(ptr)
	if strings.HasSuffix(low, ".in-addr.arpa") || strings.HasSuffix(low, ".ip6.arpa") {
		return ""
	}
	if labelLooksLikeIP(ptr, ip) {
		return ""
	}
	return ptr
}
