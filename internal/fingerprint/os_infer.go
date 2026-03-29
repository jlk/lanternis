package fingerprint

import (
	"regexp"
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

type osEvidence struct {
	family string
	detail string
	score  int
	source string
	field  string
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
		} else {
			return nil
		}
	}
	return ev
}

var (
	reSrvWinIIS   = regexp.MustCompile(`(?i)Microsoft-IIS/([0-9.]+)`)
	reSrvNginx    = regexp.MustCompile(`(?i)nginx/([0-9.]+)`)
	reSrvApache   = regexp.MustCompile(`(?i)Apache(?:/([0-9.]+))?`)
	reSrvLighttpd = regexp.MustCompile(`(?i)lighttpd/([0-9.]+)`)
	reSrvCaddy    = regexp.MustCompile(`(?i)Caddy`)
)

// inferOSFromHTTPServer extracts stack hints from the HTTP Server header (not always OS).
func inferOSFromHTTPServer(server string) *osEvidence {
	s := strings.TrimSpace(server)
	if s == "" {
		return nil
	}
	low := strings.ToLower(s)
	ev := &osEvidence{source: "os_http", field: "http_server", score: 28}
	switch {
	case reSrvWinIIS.MatchString(s):
		ev.family = OSFamilyWindows
		if m := reSrvWinIIS.FindStringSubmatch(s); len(m) > 1 {
			ev.detail = "Windows (IIS " + m[1] + ")"
		} else {
			ev.detail = "Windows (IIS)"
		}
		ev.score = 62
	case strings.Contains(low, "win32") || strings.Contains(low, "windows"):
		ev.family = OSFamilyWindows
		ev.detail = "Windows (HTTP Server header)"
		ev.score = 45
	case reSrvNginx.MatchString(s):
		ev.family = OSFamilyLinux
		if m := reSrvNginx.FindStringSubmatch(s); len(m) > 1 {
			ev.detail = "Linux-like (nginx " + m[1] + ")"
		} else {
			ev.detail = "Linux-like (nginx)"
		}
		ev.score = 35
	case reSrvApache.MatchString(s):
		ev.family = OSFamilyLinux
		ev.detail = "Linux-like (Apache)"
		ev.score = 34
	case reSrvLighttpd.MatchString(s):
		ev.family = OSFamilyLinux
		ev.detail = "Linux-like (lighttpd)"
		ev.score = 34
	case reSrvCaddy.MatchString(s):
		ev.family = OSFamilyLinux
		ev.detail = "Linux-like (Caddy)"
		ev.score = 33
	default:
		return nil
	}
	return ev
}

// inferOSFromSSDPServer parses coarse OS from SSDP SERVER: (often "Linux, UPnP/1.0, ...").
func inferOSFromSSDPServer(server string) *osEvidence {
	s := strings.TrimSpace(server)
	if s == "" {
		return nil
	}
	low := strings.ToLower(s)
	ev := &osEvidence{source: "os_ssdp", field: "ssdp_server", score: 22}
	switch {
	case strings.HasPrefix(low, "linux"):
		ev.family = OSFamilyLinux
		ev.detail = "Linux (SSDP SERVER string)"
		ev.score = 40
	case strings.Contains(low, "windows"):
		ev.family = OSFamilyWindows
		ev.detail = "Windows (SSDP SERVER string)"
		ev.score = 40
	case strings.Contains(low, "darwin") || strings.Contains(low, "mac os"):
		ev.family = OSFamilyDarwin
		ev.detail = "macOS / Darwin (SSDP SERVER string)"
		ev.score = 42
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
	ev := &osEvidence{source: "os_smb", field: "native_os", score: 75}
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

// mergeOSEvidence picks the strongest OS hint and writes Record.OSFamily / OSDetail + signals.
func mergeOSEvidence(rec *Record, evs []*osEvidence) {
	var best *osEvidence
	for _, e := range evs {
		if e == nil {
			continue
		}
		if best == nil || e.score > best.score {
			best = e
		}
	}
	if best == nil || best.family == "" {
		return
	}
	rec.OSFamily = best.family
	rec.OSDetail = best.detail
	rec.Signals = append(rec.Signals, Signal{Source: best.source, Field: best.field, Value: truncate(best.detail, 200)})
	if best.score >= 50 {
		rec.LadderMax = maxInt(rec.LadderMax, 3)
	}
}

// ApplyOSInference merges SSH, HTTP Server, SSDP SERVER, and optional SMB native strings into rec.
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
	mergeOSEvidence(rec, evs)
}
