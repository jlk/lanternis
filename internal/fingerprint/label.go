package fingerprint

import (
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxDisplayLabelRunes = 80

// DisplayLabel chooses a concise inventory label after fingerprinting. It prefers a
// meaningful network-assigned name (managed DNS / PTR, UPnP friendly name, mDNS
// human names, mDNS TXT fn=) over product summaries like "General IPC" or opaque
// device tokens. Product-ish summaries are a later fallback.
func DisplayLabel(rec *Record, hints map[string]any, ip string) string {
	if s := pickBestNetworkLabel(rec, hints, ip); s != "" {
		return trimLabel(s)
	}
	if rec != nil {
		if s := strings.TrimSpace(summarize(rec)); s != "" && !labelLooksLikeIP(s, ip) && !isUninformativeProductSummary(s) {
			return trimLabel(s)
		}
		if s := networkIdentityLabel(rec, hints, ip); s != "" {
			return trimLabel(s)
		}
		return trimLabel(firstNonEmpty(ip, fallbackHintOnlyLabel(hints, ip)))
	}
	return trimLabel(firstNonEmpty(fallbackHintOnlyLabel(hints, ip), ip))
}

func networkIdentityLabel(rec *Record, hints map[string]any, ip string) string {
	if s := firstSignal(rec, "ptr"); s != "" {
		if t := cleanPTRLabel(s, ip); t != "" {
			return t
		}
	}
	if s := firstSignal(rec, "mdns_name"); s != "" {
		if t := cleanHostishLabel(s, ip); t != "" {
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
	return pickBestNetworkLabel(nil, hints, ip)
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

// InventoryLabelFromInference builds a concise hosts.label string from a name inference (user-chosen).
// Uses the text before an em dash (guess) when present, otherwise the full text, trimmed to the display cap.
func InventoryLabelFromInference(in NameInference) string {
	t := strings.TrimSpace(in.Text)
	if t == "" {
		return ""
	}
	if i := strings.Index(t, " — "); i > 0 {
		t = strings.TrimSpace(t[:i])
	}
	return trimLabel(t)
}

// HostConfidenceFromInference maps inference confidence to the host confidence field.
func HostConfidenceFromInference(in NameInference) string {
	c := strings.ToLower(strings.TrimSpace(in.Confidence))
	switch c {
	case "high", "medium", "low":
		return c
	default:
		return "medium"
	}
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
	// Prefer short hostnames (left-most label) for display.
	// Example: sw04.mercer.jlk.dev -> sw04
	if i := strings.IndexByte(ptr, '.'); i > 0 {
		short := strings.TrimSpace(ptr[:i])
		if short != "" && !labelLooksLikeIP(short, ip) {
			return short
		}
	}
	return ptr
}

// --- Ranked network-assigned names (deterministic, evidence-backed) ---

const (
	srcPTR          = "ptr"
	srcUPnPFriendly = "upnp_friendly"
	srcMDNSTXT      = "mdns_txt"
	srcMDNSNameHint = "mdns_hint_name"
	srcMDNSInstance = "mdns_instance"
	srcMDNSSignal   = "mdns_signal"
	srcTLSCert      = "tls_hostname"
	srcHTTPTitle    = "http_title"
)

type scoredName struct {
	label  string
	score  int
	source string
}

func pickBestNetworkLabel(rec *Record, hints map[string]any, ip string) string {
	var cands []scoredName
	if rec != nil {
		for _, sig := range rec.Signals {
			switch sig.Source {
			case "ptr":
				if t := cleanPTRLabel(strings.TrimSpace(sig.Value), ip); t != "" {
					// Prefer managed DNS / DHCP-assigned PTR names over mDNS tokens when scores are close.
					cands = append(cands, scoredName{label: t, score: humanReadableNameScore(t) + 35, source: srcPTR})
				}
			case "mdns_name":
				if t := cleanHostishLabel(sig.Value, ip); t != "" {
					cands = append(cands, scoredName{label: t, score: scoreMDNSHostToken(t), source: srcMDNSSignal})
				}
			case "upnp_xml":
				if strings.EqualFold(sig.Field, "friendlyName") {
					t := strings.TrimSpace(sig.Value)
					if t != "" && !labelLooksLikeIP(t, ip) && !isUninformativeProductSummary(t) {
						cands = append(cands, scoredName{label: t, score: scoreFriendlyPhrase(t), source: srcUPnPFriendly})
					}
				}
			case "tls_cert":
				if t := tlsCandidateLabel(sig.Value, ip); t != "" {
					cands = append(cands, scoredName{label: t, score: humanReadableNameScore(t) - 8, source: srcTLSCert})
				}
			case "http_title":
				t := strings.TrimSpace(sig.Value)
				if t != "" && !isGenericPageTitle(t) {
					cands = append(cands, scoredName{label: t, score: scoreFriendlyPhrase(t) - 15, source: srcHTTPTitle})
				}
			}
		}
	}
	appendMDNSHintNameCandidates(&cands, hints, ip)
	best := mergeScoredNames(cands)
	if best.label == "" || best.score < 8 {
		return ""
	}
	return best.label
}

func appendMDNSHintNameCandidates(cands *[]scoredName, hints map[string]any, ip string) {
	mdns, ok := hints["mdns"].(map[string]any)
	if !ok {
		return
	}
	for _, n := range stringSliceFromAny(mdns["names"]) {
		if t := cleanHostishLabel(n, ip); t != "" {
			*cands = append(*cands, scoredName{label: t, score: scoreMDNSHostToken(t), source: srcMDNSNameHint})
		}
	}
	raw, ok := mdns["services"].([]any)
	if !ok {
		return
	}
	for _, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"fn", "name", "friendly"} {
			if s := txtValue(m, k); s != "" {
				t := strings.TrimSpace(s)
				if t != "" && !labelLooksLikeIP(t, ip) && !isUninformativeProductSummary(t) {
					*cands = append(*cands, scoredName{label: t, score: scoreFriendlyPhrase(t) + 6, source: srcMDNSTXT})
				}
			}
		}
		if inst, ok := m["instance"].(string); ok {
			if t := cleanServiceLabel(strings.TrimSpace(inst), ip); t != "" {
				*cands = append(*cands, scoredName{label: t, score: scoreMDNSHostToken(t) - 4, source: srcMDNSInstance})
			}
		}
		for _, pair := range stringSliceFromAny(m["txt"]) {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "fn", "name", "friendly":
				t := strings.TrimSpace(v)
				if t != "" && !labelLooksLikeIP(t, ip) && !isUninformativeProductSummary(t) {
					*cands = append(*cands, scoredName{label: t, score: scoreFriendlyPhrase(t) + 6, source: srcMDNSTXT})
				}
			default:
				lk := strings.ToLower(strings.TrimSpace(k))
				if lk == "host" && looksOpaqueDeviceToken(strings.TrimSpace(v)) {
					// Often a vendor serial token (e.g. 8H0823DPAG23ED1) — not a display name.
					continue
				}
			}
		}
	}
}

func cleanServiceLabel(inst, ip string) string {
	inst = strings.TrimSpace(strings.ReplaceAll(inst, "\x20", " "))
	if inst == "" {
		return ""
	}
	if i := strings.Index(inst, "._"); i > 0 {
		inst = inst[:i]
	}
	return cleanHostishLabel(inst, ip)
}

func mergeScoredNames(cands []scoredName) scoredName {
	best := scoredName{score: -1 << 30}
	for _, c := range cands {
		if c.label == "" {
			continue
		}
		bp := sourceRank(c.source)
		bestP := sourceRank(best.source)
		if c.score > best.score || (c.score == best.score && bp > bestP) {
			best = c
		}
	}
	if best.score == -1<<30 {
		return scoredName{}
	}
	return best
}

func sourceRank(src string) int {
	switch src {
	case srcPTR:
		return 100
	case srcUPnPFriendly:
		return 95
	case srcMDNSTXT:
		return 92
	case srcMDNSNameHint:
		return 55
	case srcMDNSInstance:
		return 52
	case srcMDNSSignal:
		return 50
	case srcTLSCert:
		return 40
	case srcHTTPTitle:
		return 30
	default:
		return 0
	}
}

func humanReadableNameScore(s string) int {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0
	}
	score := 40
	rs := []rune(s)
	letter := 0
	digit := 0
	for _, r := range rs {
		if unicode.IsLetter(r) {
			letter++
		} else if unicode.IsDigit(r) {
			digit++
		}
	}
	n := len(rs)
	if n > 0 && digit*2 >= n {
		score -= 35
	}
	if looksOpaqueDeviceToken(s) {
		score -= 45
	}
	// Delimited word-like tokens (managed DNS / DHCP hostnames).
	if strings.ContainsAny(s, "-_.") && letter >= 4 {
		score += 22
	}
	if strings.Contains(s, " ") && letter >= 6 {
		score += 18
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	})
	if len(parts) >= 2 {
		score += 14
		for _, p := range parts {
			if len(p) >= 3 && vowelRunPresent(p) {
				score += 6
			}
		}
	}
	if n > 48 {
		score -= 8
	}
	if n > 80 {
		score -= 10
	}
	return score
}

func scoreMDNSHostToken(s string) int {
	return humanReadableNameScore(s)
}

func scoreFriendlyPhrase(s string) int {
	sc := humanReadableNameScore(s)
	if strings.Contains(strings.TrimSpace(s), " ") {
		sc += 12
	}
	return sc
}

func vowelRunPresent(s string) bool {
	s = strings.ToLower(s)
	for _, v := range []byte{'a', 'e', 'i', 'o', 'u'} {
		if strings.ContainsRune(s, rune(v)) {
			return true
		}
	}
	return false
}

// looksOpaqueDeviceToken catches mDNS-ish serials like "8h0823dpag23ed1" (mixed alnum, little natural language).
func looksOpaqueDeviceToken(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 10 {
		return false
	}
	alnum := 0
	digit := 0
	letter := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			alnum++
			if r <= '9' && r >= '0' {
				digit++
			} else {
				letter++
			}
		} else if r == '-' || r == '_' {
			// ignore separators
		} else {
			return false
		}
	}
	if alnum < 10 {
		return false
	}
	if digit == 0 || letter == 0 {
		return false
	}
	// Mostly letters but ultra-low vowel density → likely product code.
	if letter > digit && !vowelRunPresent(s) {
		return true
	}
	if digit >= letter && digit*10 >= alnum*4 {
		return true
	}
	return false
}

func tlsCandidateLabel(raw, ip string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || labelLooksLikeIP(raw, ip) {
		return ""
	}
	// TLSCertNames may return comma-SAN lists; take first host-ish token.
	for _, part := range strings.Split(raw, ",") {
		t := strings.TrimSpace(part)
		t = strings.TrimPrefix(t, "DNS:")
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if net.ParseIP(strings.TrimSuffix(t, ".")) != nil {
			continue
		}
		// Wildcard or pure hex noise
		if strings.HasPrefix(t, "*.") {
			t = strings.TrimPrefix(t, "*.")
		}
		if short := cleanPTRLabel(t, ip); short != "" {
			return short
		}
	}
	return ""
}

func isGenericPageTitle(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	switch t {
	case "", "web", "home", "index", "login", "admin", "administrator", "401", "404", "403", "error":
		return true
	}
	if strings.HasPrefix(t, "http ") {
		return true
	}
	if strings.HasPrefix(t, "index of ") {
		return true
	}
	return false
}

func isUninformativeProductSummary(s string) bool {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return true
	}
	// Generic camera/NVR blobs seen on cheap IPC UPnP descriptions.
	generic := []string{
		"general ipc",
		"ip camera",
		"network camera",
		"wireless camera",
		"ipc camera",
		"hd ipc",
		"smart ipc",
		"ipcam",
		"ipc",
	}
	for _, g := range generic {
		if t == g || strings.HasPrefix(t, g+" ") || strings.HasSuffix(t, " "+g) {
			return true
		}
	}
	if strings.Contains(t, "general") && strings.Contains(t, "ipc") && utf8.RuneCountInString(t) <= 24 {
		return true
	}
	return false
}
