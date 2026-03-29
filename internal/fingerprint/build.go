package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jlk/lanternis/internal/store"
)

// Build derives a fingerprint Record from host hints, open ports, and optional HTTP/TLS/SSH probes.
// opts may be nil (equivalent to default normal profile).
func Build(ctx context.Context, h store.Host, hints map[string]any, client *http.Client, opts *BuildOptions) (*Record, error) {
	if client == nil {
		client = DefaultHTTPClient()
	}
	rec := &Record{SchemaVersion: 1}
	ports := portSet(h.OpenPorts)
	var pctx ProbeContext

	// L1: OUI from ARP MAC.
	if arp, ok := hints["arp"].(map[string]any); ok {
		if mac, ok := arp["mac"].(string); ok {
			if v := LookupVendor(mac); v != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "oui", Field: "mac_prefix", Value: v})
				rec.LadderMax = maxInt(rec.LadderMax, 1)
			}
		}
	}

	// Reverse DNS (PTR) — often encodes appliance role on local DNS / ISP resolvers.
	ptrNames, _ := LookupPTR(ctx, h.IP)
	pctx.PTRNames = ptrNames
	for _, name := range ptrNames {
		rec.Signals = append(rec.Signals, Signal{Source: "ptr", Field: "name", Value: truncate(name, 200)})
	}
	if len(ptrNames) > 0 {
		rec.LadderMax = maxInt(rec.LadderMax, 2)
	}

	// UPnP device description (L4 when model/manufacturer present).
	if ssdp, ok := hints["ssdp"].(map[string]any); ok {
		if loc, ok := ssdp["location"].(string); ok && strings.TrimSpace(loc) != "" {
			loc = strings.TrimSpace(loc)
			dev, err := FetchUPnPDeviceDescription(ctx, client, loc)
			if err == nil {
				if dev.Manufacturer != "" {
					rec.Manufacturer = dev.Manufacturer
				}
				if dev.ModelName != "" {
					rec.Model = dev.ModelName
				} else if dev.ModelNumber != "" {
					rec.Model = dev.ModelNumber
				}
				if dev.SerialNumber != "" {
					rec.Serial = dev.SerialNumber
				}
				if dev.SoftwareVersion != "" {
					rec.FirmwareVersion = dev.SoftwareVersion
					rec.Signals = append(rec.Signals, Signal{Source: "upnp_xml", Field: "softwareVersion", Value: truncate(dev.SoftwareVersion, 120)})
					rec.LadderMax = maxInt(rec.LadderMax, 3)
				}
				if dev.ModelDescription != "" {
					rec.Signals = append(rec.Signals, Signal{Source: "upnp_xml", Field: "modelDescription", Value: truncate(dev.ModelDescription, 240)})
				}
				rec.Signals = append(rec.Signals, Signal{Source: "upnp_xml", Field: "location", Value: truncate(loc, 120)})
				if dev.Manufacturer != "" || dev.ModelName != "" || dev.ModelNumber != "" {
					rec.LadderMax = maxInt(rec.LadderMax, 4)
				} else if dev.FriendlyName != "" {
					rec.Signals = append(rec.Signals, Signal{Source: "upnp_xml", Field: "friendlyName", Value: dev.FriendlyName})
					rec.LadderMax = maxInt(rec.LadderMax, 3)
				}
			}
		}
	}

	// mDNS names — at least L3; treat rich hostnames as L4 model hint when empty.
	if mdns, ok := hints["mdns"].(map[string]any); ok {
		var mdnsNameModelCandidate string
		if names := stringSliceFromAny(mdns["names"]); len(names) > 0 {
			for _, n := range names {
				n = strings.TrimSpace(n)
				if n == "" {
					continue
				}
				rec.Signals = append(rec.Signals, Signal{Source: "mdns_name", Field: "name", Value: n})
			}
			rec.LadderMax = maxInt(rec.LadderMax, 3)
			first := strings.TrimSpace(names[0])
			if looksLikeProductToken(first) {
				mdnsNameModelCandidate = first
			}
		}

		// mDNS service types / TXT. These are strong L2–L3 signals and sometimes carry model strings.
		if raw, ok := mdns["services"].([]any); ok && len(raw) > 0 {
			seenTy := make(map[string]struct{})
			for _, e := range raw {
				m, ok := e.(map[string]any)
				if !ok {
					continue
				}
				ty, _ := m["type"].(string)
				ty = strings.TrimSpace(strings.ToLower(ty))
				if ty == "" {
					continue
				}
				port := 0
				switch x := m["port"].(type) {
				case float64:
					port = int(x)
				case int:
					port = x
				case int64:
					port = int(x)
				}
				txt := stringSliceFromAny(m["txt"])
				pctx.MDNSServices = append(pctx.MDNSServices, MDNSServiceHint{Type: ty, Port: port, TXT: txt})
				if _, ok := seenTy[ty]; !ok {
					seenTy[ty] = struct{}{}
					rec.Signals = append(rec.Signals, Signal{Source: "mdns_service", Field: "type", Value: truncate(ty, 160)})
				}
				if len(txt) > 0 {
					// Only include a few compact TXT strings to avoid huge evidence.
					for i := 0; i < len(txt) && i < 4; i++ {
						if strings.TrimSpace(txt[i]) == "" {
							continue
						}
						rec.Signals = append(rec.Signals, Signal{Source: "mdns_txt", Field: ty, Value: truncate(txt[i], 160)})
					}
					// Extract model-like tokens from common TXT k=v.
					if rec.Model == "" {
						if v := mdnsModelFromTXT(txt); v != "" {
							rec.Model = v
							rec.LadderMax = maxInt(rec.LadderMax, 4)
						}
					}
				}
				rec.LadderMax = maxInt(rec.LadderMax, 3)
			}
		}

		// Apply hostname-derived model only if we still don't have a better one.
		if rec.Model == "" && mdnsNameModelCandidate != "" {
			rec.Model = mdnsNameModelCandidate
			rec.LadderMax = maxInt(rec.LadderMax, 4)
		}
	}

	needProbe := rec.LadderMax < 4 || rec.Model == ""

	// HTTP(S) on open web ports — title, Server header, and classification keywords.
	if ports["80"] {
		title, server, err := FetchHTTPIndexMeta(ctx, client, "http", h.IP, "80")
		if err == nil {
			pctx.HTTPTitle80 = title
			pctx.HTTPServer80 = server
			if title != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_title", Field: "title", Value: truncate(title, 200)})
				if needProbe && rec.Model == "" {
					rec.Model = title
				}
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
			if server != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_server", Field: "server", Value: truncate(server, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 3)
			}
		}
	}
	if ports["443"] {
		title, server, err := FetchHTTPIndexMeta(ctx, client, "https", h.IP, "443")
		if err == nil {
			pctx.HTTPTitle443 = title
			pctx.HTTPServer443 = server
			if title != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_title", Field: "title_https", Value: truncate(title, 200)})
				if needProbe && rec.Model == "" {
					rec.Model = title
				}
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
			if server != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_server", Field: "server_https", Value: truncate(server, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 3)
			}
		}
		cn, err := TLSCertNames(ctx, h.IP, "443")
		if err == nil && cn != "" {
			pctx.TLSCN = cn
			rec.Signals = append(rec.Signals, Signal{Source: "tls_cert", Field: "dns_or_cn", Value: truncate(cn, 200)})
			rec.LadderMax = maxInt(rec.LadderMax, 4)
			if needProbe && rec.Model == "" {
				rec.Model = cn
			}
		}
	}
	if ports["22"] {
		banner, err := FetchSSHBanner(ctx, h.IP, "22")
		if err == nil && banner != "" {
			pctx.SSHBanner = banner
			rec.Signals = append(rec.Signals, Signal{Source: "ssh_banner", Field: "line", Value: truncate(banner, 200)})
			rec.LadderMax = maxInt(rec.LadderMax, 4)
		}
	}

	// Alternate web admin ports (already in TCP profiles for light+).
	if ports["8080"] {
		title, server, err := FetchHTTPIndexMeta(ctx, client, "http", h.IP, "8080")
		if err == nil {
			pctx.HTTPTitle8080 = title
			pctx.HTTPServer8080 = server
			if title != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_title", Field: "title_8080", Value: truncate(title, 200)})
				if needProbe && rec.Model == "" {
					rec.Model = title
				}
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
			if server != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_server", Field: "server_8080", Value: truncate(server, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 3)
			}
		}
	}
	if ports["8443"] {
		title, server, err := FetchHTTPIndexMeta(ctx, client, "https", h.IP, "8443")
		if err == nil {
			pctx.HTTPTitle8443 = title
			pctx.HTTPServer8443 = server
			if title != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_title", Field: "title_8443", Value: truncate(title, 200)})
				if needProbe && rec.Model == "" {
					rec.Model = title
				}
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
			if server != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_server", Field: "server_8443", Value: truncate(server, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 3)
			}
		}
		cn, err := TLSCertNames(ctx, h.IP, "8443")
		if err == nil && cn != "" {
			pctx.TLSCN8443 = cn
			rec.Signals = append(rec.Signals, Signal{Source: "tls_cert", Field: "dns_or_cn_8443", Value: truncate(cn, 200)})
			rec.LadderMax = maxInt(rec.LadderMax, 4)
			if needProbe && rec.Model == "" {
				rec.Model = cn
			}
		}
	}
	if ports["8888"] {
		title, server, err := FetchHTTPIndexMeta(ctx, client, "http", h.IP, "8888")
		if err == nil {
			pctx.HTTPTitle8888 = title
			pctx.HTTPServer8888 = server
			if title != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_title", Field: "title_8888", Value: truncate(title, 200)})
				if needProbe && rec.Model == "" {
					rec.Model = title
				}
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
			if server != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_server", Field: "server_8888", Value: truncate(server, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 3)
			}
		}
	}

	// SMB native OS / LAN (445) — anonymous SMB1 extended security where supported.
	if ports["445"] {
		if os, lan := FetchSMBNativeStrings(ctx, h.IP, "445"); os != "" || lan != "" {
			pctx.SMBNativeOS, pctx.SMBNativeLAN = os, lan
		}
	}

	// RDP negotiation peek (3389).
	if ports["3389"] {
		if hint := FetchRDPNegotiationHint(ctx, h.IP, "3389"); hint != "" {
			pctx.RDPHint = hint
		}
	}

	// Raw SYN/SYN-ACK TCP fingerprint (Linux + CAP_NET_RAW / root; deep scan only — explicit).
	if tcpProfileDeep(opts) {
		if dport := firstOpenPortForStackProbe(ports); dport != "" {
			if hint := probeTCPStackHint(ctx, h.IP, dport); hint != "" {
				pctx.TCPStackHint = hint
			}
		}
	}

	ApplyOSInference(rec, hints, pctx)

	ClassifyDevice(rec, h, hints, pctx)

	rec.Summary = summarize(rec)
	if rec.LadderMax == 0 && len(rec.Signals) == 0 {
		return nil, nil
	}
	return rec, nil
}

// RecordJSON marshals a record for hosts.fingerprint_blob.
func RecordJSON(rec *Record) (string, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ConfidenceFor returns a store confidence string for the record.
func ConfidenceFor(rec *Record) string {
	if rec == nil {
		return "unknown"
	}
	switch {
	case rec.LadderMax >= 4:
		return "medium"
	case rec.LadderMax >= 2:
		return "low"
	case rec.LadderMax >= 1:
		return "low"
	default:
		return "unknown"
	}
}

func summarize(rec *Record) string {
	if rec.Manufacturer != "" && rec.Model != "" {
		s := rec.Manufacturer + " " + rec.Model
		if rec.FirmwareVersion != "" {
			s += " (" + rec.FirmwareVersion + ")"
		}
		return strings.TrimSpace(s)
	}
	if rec.Model != "" {
		return strings.TrimSpace(rec.Model)
	}
	if rec.Manufacturer != "" && rec.FirmwareVersion != "" {
		return strings.TrimSpace(rec.Manufacturer + " (" + rec.FirmwareVersion + ")")
	}
	if rec.FirmwareVersion != "" {
		return strings.TrimSpace(rec.FirmwareVersion)
	}
	if rec.Manufacturer != "" {
		return strings.TrimSpace(rec.Manufacturer)
	}
	// Fall back to first strong signal value.
	for _, sig := range rec.Signals {
		if sig.Source == "oui" && sig.Value != "" {
			return "NIC: " + sig.Value
		}
	}
	for _, sig := range rec.Signals {
		if sig.Value != "" && (sig.Source == "http_title" || sig.Source == "tls_cert") {
			return sig.Value
		}
	}
	for _, sig := range rec.Signals {
		if sig.Source == "ssh_banner" && sig.Value != "" {
			return sig.Value
		}
	}
	if rec.DeviceClass != "" {
		return rec.DeviceClass
	}
	return ""
}

func firstOpenPortForStackProbe(ports map[string]bool) string {
	for _, p := range []string{"443", "80", "22", "445", "3389", "8080"} {
		if ports[p] {
			return p
		}
	}
	return ""
}

func portSet(ports []string) map[string]bool {
	m := make(map[string]bool)
	for _, p := range ports {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "icmp" {
			continue
		}
		m[p] = true
	}
	return m
}

func stringSliceFromAny(v any) []string {
	switch x := v.(type) {
	case string:
		x = strings.TrimSpace(x)
		if x == "" {
			return nil
		}
		return []string{x}
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func looksLikeProductToken(s string) bool {
	if len(s) < 4 {
		return false
	}
	// Heuristic: digits, brackets, or common device-ish tokens in mDNS names.
	if strings.ContainsAny(s, "0123456789[]()") {
		return true
	}
	lower := strings.ToLower(s)
	return strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") ||
		strings.Contains(lower, "android") || strings.Contains(lower, "samsung") ||
		strings.Contains(lower, "windows") || strings.Contains(lower, "macbook")
}

func mdnsModelFromTXT(txt []string) string {
	for _, t := range txt {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "md", "model", "ty", "product", "device", "hw":
			if len(v) >= 3 {
				return truncate(v, 120)
			}
		}
	}
	return ""
}
