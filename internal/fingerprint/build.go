package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jlk/lanternis/internal/store"
)

// Build derives a fingerprint Record from host hints, open ports, and optional HTTP/TLS/SSH probes.
func Build(ctx context.Context, h store.Host, hints map[string]any, client *http.Client) (*Record, error) {
	if client == nil {
		client = DefaultHTTPClient()
	}
	rec := &Record{SchemaVersion: 1}
	ports := portSet(h.OpenPorts)

	// L1: OUI from ARP MAC.
	if arp, ok := hints["arp"].(map[string]any); ok {
		if mac, ok := arp["mac"].(string); ok {
			if v := LookupVendor(mac); v != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "oui", Field: "mac_prefix", Value: v})
				rec.LadderMax = maxInt(rec.LadderMax, 1)
			}
		}
	}

	// UPnP device description (L4 when model/manufacturer present).
	if ssdp, ok := hints["ssdp"].(map[string]any); ok {
		if loc, ok := ssdp["location"].(string); ok && strings.TrimSpace(loc) != "" {
			dev, err := FetchUPnPDeviceDescription(ctx, client, strings.TrimSpace(loc))
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
			if rec.Model == "" && looksLikeProductToken(first) {
				rec.Model = first
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
		}
	}

	// Active probes when ports open and we still lack strong L4.
	needProbe := rec.LadderMax < 4 || rec.Model == ""
	if needProbe {
		if ports["80"] {
			if title, err := FetchHTTPTitle(ctx, client, h.IP, "80"); err == nil && title != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "http_title", Field: "title", Value: truncate(title, 200)})
				if rec.Model == "" && title != "" {
					rec.Model = title
				}
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
		}
		if ports["443"] {
			if cn, err := TLSCertNames(ctx, h.IP, "443"); err == nil && cn != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "tls_cert", Field: "dns_or_cn", Value: truncate(cn, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 4)
				if rec.Model == "" {
					rec.Model = cn
				}
			}
		}
		if ports["22"] {
			if banner, err := FetchSSHBanner(ctx, h.IP, "22"); err == nil && banner != "" {
				rec.Signals = append(rec.Signals, Signal{Source: "ssh_banner", Field: "line", Value: truncate(banner, 200)})
				rec.LadderMax = maxInt(rec.LadderMax, 4)
			}
		}
	}

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
