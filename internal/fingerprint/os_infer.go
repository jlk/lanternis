package fingerprint

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// OS family tokens stored in Record.OSFamily (coarse, comparable).
const (
	OSFamilyLinux    = "linux"
	OSFamilyWindows  = "windows"
	OSFamilyDarwin   = "darwin"
	OSFamilyFreeBSD  = "freebsd"
	OSFamilyOpenBSD  = "openbsd"
	OSFamilyNetBSD   = "netbsd"
	OSFamilyEmbedded = "embedded"
	OSFamilyUnknown  = "unknown"
)

// Evidence tiers for fusion: strong (banners, SMB, IIS), medium (RDP, TCP rule match, mDNS),
// weak (generic HTTP/SSDP/UPnP text — not OS by themselves).
const (
	tierWeak = iota + 1
	tierMedium
	tierStrong
)

type osEvidence struct {
	family string
	detail string
	score  int
	source string
	field  string
	tier   int
}

var (
	reSSHDebian = regexp.MustCompile(`(?i)Debian`)
	reSSHUbuntu = regexp.MustCompile(`(?i)Ubuntu[_-]?([0-9.]+)?`)
	reSSHRHEL   = regexp.MustCompile(`(?i)Red Hat Enterprise Linux|RHEL`)
	reSSHFedora = regexp.MustCompile(`(?i)Fedora( Linux)?`)
	reSSHAlma   = regexp.MustCompile(`(?i)AlmaLinux`)
	reSSHRocky  = regexp.MustCompile(`(?i)Rocky Linux`)
	reSSHAlpine = regexp.MustCompile(`(?i)Alpine`)
	reSSHArches = regexp.MustCompile(`(?i)Arch Linux`)
	reOpenSSH   = regexp.MustCompile(`OpenSSH[_-]([0-9][0-9a-z._-]*)`)

	// Patch level often encodes distro (e.g. Ubuntu-22.04).
	reUbuntuPatch = regexp.MustCompile(`(?i)Ubuntu[_-]([0-9.]+)`)
	reDebianPatch = regexp.MustCompile(`(?i)Debian[_-]([0-9]+(?:\.[0-9]+)*)`)
)

// inferOSFromSSH parses OpenSSH banners and optional Debian/Ubuntu patch tokens.
func inferOSFromSSH(banner string) *osEvidence {
	b := strings.TrimSpace(banner)
	if b == "" || !strings.HasPrefix(strings.ToUpper(b), "SSH-") {
		return nil
	}
	ev := &osEvidence{source: "os_ssh", field: "ssh_banner", score: 55}
	switch {
	case reSSHUbuntu.MatchString(b):
		ev.family = OSFamilyLinux
		if m := reUbuntuPatch.FindStringSubmatch(b); len(m) > 1 {
			ev.detail = "Ubuntu " + m[1] + " (SSH banner patch)"
		} else if m := reSSHUbuntu.FindStringSubmatch(b); len(m) > 1 && strings.TrimSpace(m[1]) != "" {
			ev.detail = "Ubuntu " + m[1] + " (SSH banner)"
		} else {
			ev.detail = "Ubuntu (SSH banner)"
		}
		ev.score = 72
	case reSSHDebian.MatchString(b):
		ev.family = OSFamilyLinux
		if m := reDebianPatch.FindStringSubmatch(b); len(m) > 1 {
			ev.detail = "Debian " + m[1] + " (SSH banner patch)"
		} else {
			ev.detail = "Debian (SSH banner)"
		}
		ev.score = 70
	case reSSHRHEL.MatchString(b):
		ev.family = OSFamilyLinux
		ev.detail = "RHEL (SSH banner)"
		ev.score = 68
	case reSSHAlma.MatchString(b):
		ev.family = OSFamilyLinux
		ev.detail = "AlmaLinux (SSH banner)"
		ev.score = 66
	case reSSHRocky.MatchString(b):
		ev.family = OSFamilyLinux
		ev.detail = "Rocky Linux (SSH banner)"
		ev.score = 66
	case reSSHFedora.MatchString(b):
		ev.family = OSFamilyLinux
		ev.detail = "Fedora (SSH banner)"
		ev.score = 65
	case reSSHAlpine.MatchString(b):
		ev.family = OSFamilyLinux
		ev.detail = "Alpine (SSH banner)"
		ev.score = 64
	case reSSHArches.MatchString(b):
		ev.family = OSFamilyLinux
		ev.detail = "Arch Linux (SSH banner)"
		ev.score = 64
	case strings.Contains(strings.ToLower(b), "freebsd"):
		ev.family = OSFamilyFreeBSD
		ev.detail = "FreeBSD (SSH banner)"
		ev.score = 68
	case strings.Contains(strings.ToLower(b), "openbsd"):
		ev.family = OSFamilyOpenBSD
		ev.detail = "OpenBSD (SSH banner)"
		ev.score = 68
	default:
		if m := reOpenSSH.FindStringSubmatch(b); len(m) > 0 {
			ev.family = OSFamilyUnknown
			ev.detail = "OpenSSH " + m[1] + " (daemon only — OS not identified)"
			ev.score = 38
			ev.tier = tierWeak
			return ev
		}
		return nil
	}
	ev.tier = tierStrong
	return ev
}

var (
	reSrvWinIIS   = regexp.MustCompile(`(?i)Microsoft-IIS/([0-9.]+)`)
	reSrvNginx    = regexp.MustCompile(`(?i)nginx/([0-9.]+)`)
	reSrvApache   = regexp.MustCompile(`(?i)Apache(?:/([0-9.]+))?`)
	reSrvLighttpd = regexp.MustCompile(`(?i)lighttpd/([0-9.]+)`)
	reSrvCaddy    = regexp.MustCompile(`(?i)Caddy`)
)

// inferOSFromHTTPServer extracts stack hints. Generic web servers do not imply OS (nginx runs everywhere).
func inferOSFromHTTPServer(server string) *osEvidence {
	s := strings.TrimSpace(server)
	if s == "" {
		return nil
	}
	low := strings.ToLower(s)
	ev := &osEvidence{source: "os_http", field: "http_server", tier: tierWeak, family: OSFamilyUnknown}
	switch {
	case reSrvWinIIS.MatchString(s):
		ev.family = OSFamilyWindows
		ev.tier = tierStrong
		if m := reSrvWinIIS.FindStringSubmatch(s); len(m) > 1 {
			ev.detail = "Windows (IIS " + m[1] + ")"
		} else {
			ev.detail = "Windows (IIS)"
		}
		ev.score = 62
	case strings.Contains(low, "win32") || strings.Contains(low, "windows"):
		ev.family = OSFamilyWindows
		ev.tier = tierStrong
		ev.detail = "Windows (HTTP Server header)"
		ev.score = 45
	case reSrvNginx.MatchString(s):
		if m := reSrvNginx.FindStringSubmatch(s); len(m) > 1 {
			ev.detail = "nginx " + m[1] + " (HTTP Server — not OS)"
		} else {
			ev.detail = "nginx (HTTP Server — not OS)"
		}
		ev.score = 22
	case reSrvApache.MatchString(s):
		ev.detail = "Apache (HTTP Server — not OS)"
		ev.score = 21
	case reSrvLighttpd.MatchString(s):
		if m := reSrvLighttpd.FindStringSubmatch(s); len(m) > 1 {
			ev.detail = "lighttpd " + m[1] + " (HTTP Server — not OS)"
		} else {
			ev.detail = "lighttpd (HTTP Server — not OS)"
		}
		ev.score = 21
	case reSrvCaddy.MatchString(s):
		ev.detail = "Caddy (HTTP Server — not OS)"
		ev.score = 20
	default:
		return nil
	}
	return ev
}

// inferOSFromSSDPServer records SSDP SERVER text; OS keywords are weak (many IoT stacks misreport).
func inferOSFromSSDPServer(server string) *osEvidence {
	s := strings.TrimSpace(server)
	if s == "" {
		return nil
	}
	low := strings.ToLower(s)
	ev := &osEvidence{source: "os_ssdp", field: "ssdp_server", tier: tierWeak, family: OSFamilyUnknown, score: 26}
	switch {
	case strings.HasPrefix(low, "linux"):
		ev.detail = "SSDP SERVER mentions Linux (not reliable OS ID)"
	case strings.Contains(low, "windows"):
		ev.detail = "SSDP SERVER mentions Windows (not reliable OS ID)"
	case strings.Contains(low, "darwin") || strings.Contains(low, "mac os"):
		ev.detail = "SSDP SERVER mentions Darwin/macOS (not reliable OS ID)"
	default:
		return nil
	}
	return ev
}

func inferOSFromSMBNative(nativeOS, nativeLAN string) *osEvidence {
	nativeOS = strings.TrimSpace(nativeOS)
	nativeLAN = strings.TrimSpace(nativeLAN)
	if nativeOS == "" && nativeLAN == "" {
		return nil
	}
	ev := &osEvidence{source: "os_smb", field: "native_os", score: 75, tier: tierStrong}
	combined := strings.ToLower(nativeOS + " " + nativeLAN)
	switch {
	case strings.Contains(combined, "windows"):
		ev.family = OSFamilyWindows
		if nativeOS != "" {
			ev.detail = nativeOS + " (SMB session)"
		} else {
			ev.detail = nativeLAN + " (SMB session)"
		}
		ev.score = 82
	case strings.Contains(combined, "samba"):
		ev.family = OSFamilyLinux
		if nativeOS != "" {
			ev.detail = nativeOS + " (SMB session)"
		} else {
			ev.detail = nativeLAN + " (SMB session)"
		}
		ev.score = 78
	case strings.Contains(combined, "synology") || strings.Contains(combined, "dsm"):
		ev.family = OSFamilyLinux
		ev.detail = pickFirstString(nativeOS, nativeLAN) + " (SMB session)"
		ev.score = 76
	default:
		if nativeOS != "" {
			ev.family = OSFamilyUnknown
			ev.detail = nativeOS + " (SMB session)"
			ev.score = 60
		} else {
			ev.family = OSFamilyUnknown
			ev.detail = nativeLAN + " (SMB session)"
			ev.score = 55
		}
	}
	return ev
}

func pickFirstString(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}

// mergeOSEvidence fuses tiered evidence: strong/medium with a real OS family win over weak banner text.
// Weak-only inputs never assign a concrete OS family.
func mergeOSEvidence(rec *Record, evs []*osEvidence) {
	var clean []*osEvidence
	for _, e := range evs {
		if e == nil {
			continue
		}
		clean = append(clean, e)
	}
	if len(clean) == 0 {
		return
	}

	var decisive []*osEvidence
	for _, e := range clean {
		if e.family != "" && e.family != OSFamilyUnknown {
			decisive = append(decisive, e)
		}
	}
	sort.Slice(decisive, func(i, j int) bool {
		if decisive[i].tier != decisive[j].tier {
			return decisive[i].tier > decisive[j].tier
		}
		if decisive[i].score != decisive[j].score {
			return decisive[i].score > decisive[j].score
		}
		return decisive[i].source < decisive[j].source
	})

	if len(decisive) == 0 {
		sort.Slice(clean, func(i, j int) bool {
			if clean[i].score != clean[j].score {
				return clean[i].score > clean[j].score
			}
			return clean[i].source < clean[j].source
		})
		rec.OSFamily = OSFamilyUnknown
		rec.OSDetail = clean[0].detail
		for _, e := range clean {
			rec.Signals = append(rec.Signals, Signal{Source: e.source, Field: e.field, Value: truncate(e.detail, 200)})
		}
		return
	}

	best := decisive[0]
	for _, e := range decisive[1:] {
		if e.family != best.family && e.score >= 50 && best.score >= 50 {
			rec.OSConflict = true
			rec.OSFamily = OSFamilyUnknown
			rec.OSDetail = "Conflicting OS hints: " + best.detail + " vs " + e.detail
			rec.Signals = append(rec.Signals, Signal{Source: best.source, Field: best.field, Value: truncate(best.detail, 200)})
			rec.Signals = append(rec.Signals, Signal{Source: e.source, Field: e.field, Value: truncate(e.detail, 200)})
			rec.LadderMax = maxInt(rec.LadderMax, 3)
			return
		}
	}
	rec.OSFamily = best.family
	rec.OSDetail = best.detail
	rec.Signals = append(rec.Signals, Signal{Source: best.source, Field: best.field, Value: truncate(best.detail, 200)})
	if best.score >= 50 {
		rec.LadderMax = maxInt(rec.LadderMax, 3)
	}
}

func inferOSFromRDP(hint string) *osEvidence {
	h := strings.TrimSpace(hint)
	if h == "" {
		return nil
	}
	return &osEvidence{
		source: "os_rdp",
		field:  "rdp_neg",
		family: OSFamilyWindows,
		detail: h + " (RDP)",
		score:  52,
		tier:   tierMedium,
	}
}

func inferOSFromTCPStack(hint string) *osEvidence {
	h := strings.TrimSpace(hint)
	if h == "" {
		return nil
	}
	const guessSep = " | guess="
	if i := strings.Index(h, guessSep); i >= 0 {
		rest := h[i+len(guessSep):]
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 2 {
			fam := strings.TrimSpace(parts[0])
			detail := strings.TrimSpace(parts[1])
			ev := &osEvidence{source: "os_tcp_stack", field: "syn_ack", tier: tierMedium, score: 50}
			ev.detail = strings.TrimSpace(h[:i]) + " — " + detail
			switch strings.ToLower(fam) {
			case OSFamilyLinux:
				ev.family = OSFamilyLinux
			case OSFamilyWindows:
				ev.family = OSFamilyWindows
			case OSFamilyEmbedded:
				ev.family = OSFamilyEmbedded
			default:
				ev.family = OSFamilyUnknown
				ev.tier = tierWeak
				ev.score = 30
			}
			return ev
		}
	}
	ttl, ok := parseTTLFromStackHint(h)
	if !ok {
		return nil
	}
	ev := &osEvidence{source: "os_tcp_stack", field: "syn_ack", tier: tierWeak, family: OSFamilyUnknown, score: 28}
	switch {
	case ttl <= 64:
		ev.detail = h + " (TTL≤64 — weak hint; use deep scan for TCP rule match)"
		ev.score = 24
	case ttl <= 128:
		ev.detail = h + " (TTL≤128 — weak hint; use deep scan for TCP rule match)"
		ev.score = 24
	default:
		ev.detail = h + " (TTL alone is a weak signal)"
		ev.score = 20
	}
	return ev
}

func parseTTLFromStackHint(s string) (int, bool) {
	i := strings.Index(s, "ttl=")
	if i < 0 {
		return 0, false
	}
	i += 4
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == i {
		return 0, false
	}
	v, err := strconv.Atoi(s[i:j])
	if err != nil {
		return 0, false
	}
	return v, true
}

func inferOSFromMDNSTXT(svcs []MDNSServiceHint) *osEvidence {
	var b strings.Builder
	for _, s := range svcs {
		for _, t := range s.TXT {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			k, v, ok := strings.Cut(t, "=")
			if !ok {
				b.WriteString(t)
				b.WriteByte(' ')
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)
			switch k {
			case "os", "ostype", "platform", "system":
				b.WriteString(v)
				b.WriteByte(' ')
			}
		}
	}
	low := strings.ToLower(b.String())
	if low == "" {
		return nil
	}
	ev := &osEvidence{source: "os_mdns_txt", field: "txt", tier: tierMedium, score: 44}
	switch {
	case strings.Contains(low, "windows"):
		ev.family = OSFamilyWindows
		ev.detail = "Windows (mDNS TXT)"
		ev.score = 50
	case strings.Contains(low, "android"):
		ev.family = OSFamilyLinux
		ev.detail = "Android (mDNS TXT)"
		ev.score = 48
	case strings.Contains(low, "iphone") || strings.Contains(low, "ios"):
		ev.family = OSFamilyDarwin
		ev.detail = "iOS / Apple (mDNS TXT)"
		ev.score = 48
	default:
		return nil
	}
	return ev
}

func inferOSFromUPnPDescription(text string) *osEvidence {
	t := strings.TrimSpace(text)
	if t == "" {
		return nil
	}
	low := strings.ToLower(t)
	ev := &osEvidence{source: "os_upnp_text", field: "modelDescription", tier: tierWeak, family: OSFamilyUnknown, score: 30}
	switch {
	case strings.Contains(low, "windows") && strings.Contains(low, "microsoft"):
		ev.detail = "UPnP description mentions Windows (not OS by itself)"
	case strings.Contains(low, "linux"):
		ev.detail = "UPnP description mentions Linux (not OS by itself)"
	default:
		return nil
	}
	return ev
}

// ApplyOSInference merges SSH, HTTP Server, SSDP, SMB, RDP, TCP stack, mDNS TXT, and UPnP text into rec.
func ApplyOSInference(rec *Record, hints map[string]any, pctx ProbeContext) {
	var evs []*osEvidence
	if pctx.SSHBanner != "" {
		if ev := inferOSFromSSH(pctx.SSHBanner); ev != nil {
			evs = append(evs, ev)
		}
	}
	for _, srv := range []string{
		pctx.HTTPServer80, pctx.HTTPServer443, pctx.HTTPServer8080,
		pctx.HTTPServer8443, pctx.HTTPServer8888,
	} {
		if srv == "" {
			continue
		}
		if ev := inferOSFromHTTPServer(srv); ev != nil {
			evs = append(evs, ev)
		}
	}
	if ssdp, ok := hints["ssdp"].(map[string]any); ok {
		if srv, ok := ssdp["server"].(string); ok {
			if ev := inferOSFromSSDPServer(srv); ev != nil {
				evs = append(evs, ev)
			}
		}
	}
	for _, sig := range rec.Signals {
		if sig.Source == "upnp_xml" && sig.Field == "modelDescription" && sig.Value != "" {
			if ev := inferOSFromUPnPDescription(sig.Value); ev != nil {
				evs = append(evs, ev)
			}
		}
	}
	if ev := inferOSFromMDNSTXT(pctx.MDNSServices); ev != nil {
		evs = append(evs, ev)
	}
	if pctx.SMBNativeOS != "" || pctx.SMBNativeLAN != "" {
		if ev := inferOSFromSMBNative(pctx.SMBNativeOS, pctx.SMBNativeLAN); ev != nil {
			evs = append(evs, ev)
		}
	}
	if pctx.RDPHint != "" {
		if ev := inferOSFromRDP(pctx.RDPHint); ev != nil {
			evs = append(evs, ev)
		}
	}
	if pctx.TCPStackHint != "" {
		if ev := inferOSFromTCPStack(pctx.TCPStackHint); ev != nil {
			evs = append(evs, ev)
		}
	}
	mergeOSEvidence(rec, evs)
}
