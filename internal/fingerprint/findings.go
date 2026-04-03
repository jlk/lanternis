package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/jlk/lanternis/internal/store"
)

var reOpenSSHVer = regexp.MustCompile(`(?i)OpenSSH[_-]([0-9][0-9a-z._-]*)`)

// FindingsFromRecord derives vuln-oriented findings from a persisted fingerprint Record.
func FindingsFromRecord(rec *Record) []store.Finding {
	if rec == nil {
		return nil
	}
	var out []store.Finding
	if hasGranularUPnP(rec) {
		appendUPnPGranularFindings(rec, &out)
	} else {
		appendLegacyUPnPCombined(rec, &out)
	}
	appendMDNSTXTFindings(rec, &out)
	appendHTTPExtractFindings(rec, &out)
	appendTLSWeakFindings(rec, &out)
	appendSSHFindings(rec, &out)
	appendNmapFindings(rec, &out)
	appendRTSPFindings(rec, &out)
	return out
}

func hasGranularUPnP(rec *Record) bool {
	for _, s := range rec.Signals {
		if s.Source != "upnp_xml" {
			continue
		}
		switch s.Field {
		case "manufacturer", "modelName", "modelNumber", "softwareVersion":
			if strings.TrimSpace(s.Value) != "" {
				return true
			}
		}
	}
	return false
}

func appendUPnPGranularFindings(rec *Record, out *[]store.Finding) {
	for _, s := range rec.Signals {
		if s.Source != "upnp_xml" {
			continue
		}
		v := strings.TrimSpace(s.Value)
		if v == "" {
			continue
		}
		switch s.Field {
		case "manufacturer":
			*out = append(*out, store.Finding{
				Surface:           "upnp/manufacturer",
				VendorGuess:       v,
				VersionConfidence: "high",
				EvidenceKind:      "upnp_manufacturer",
				EvidenceDigest:    digestEvidence(v),
				VulnReady:         false,
			})
		case "modelName":
			*out = append(*out, store.Finding{
				Surface:           "upnp/modelName",
				ProductGuess:      v,
				VersionConfidence: "high",
				EvidenceKind:      "upnp_modelName",
				EvidenceDigest:    digestEvidence(v),
				VulnReady:         false,
			})
		case "modelNumber":
			*out = append(*out, store.Finding{
				Surface:           "upnp/modelNumber",
				ProductGuess:      v,
				VersionConfidence: "high",
				EvidenceKind:      "upnp_modelNumber",
				EvidenceDigest:    digestEvidence(v),
				VulnReady:         false,
			})
		case "softwareVersion":
			*out = append(*out, store.Finding{
				Surface:           "upnp/softwareVersion",
				VersionGuess:      v,
				VersionConfidence: "high",
				EvidenceKind:      "upnp_softwareVersion",
				EvidenceDigest:    digestEvidence(v),
				VulnReady:         true,
			})
		}
	}
}

func appendLegacyUPnPCombined(rec *Record, out *[]store.Finding) {
	if strings.TrimSpace(rec.Manufacturer) == "" && strings.TrimSpace(rec.Model) == "" && strings.TrimSpace(rec.FirmwareVersion) == "" {
		return
	}
	conf := "low"
	vr := false
	if strings.TrimSpace(rec.FirmwareVersion) != "" {
		conf = "high"
		vr = true
	} else if strings.TrimSpace(rec.Manufacturer) != "" && strings.TrimSpace(rec.Model) != "" {
		conf = "medium"
	}
	ev := strings.TrimSpace(rec.Manufacturer + "|" + rec.Model + "|" + rec.FirmwareVersion)
	*out = append(*out, store.Finding{
		Surface:           "upnp/device",
		VendorGuess:       strings.TrimSpace(rec.Manufacturer),
		ProductGuess:      strings.TrimSpace(rec.Model),
		VersionGuess:      strings.TrimSpace(rec.FirmwareVersion),
		VersionConfidence: conf,
		EvidenceKind:      "upnp_device_xml",
		EvidenceDigest:    digestEvidence(ev),
		VulnReady:         vr,
	})
}

func appendMDNSTXTFindings(rec *Record, out *[]store.Finding) {
	for _, s := range rec.Signals {
		if s.Source != "mdns_txt" || strings.TrimSpace(s.Value) == "" {
			continue
		}
		svc := strings.TrimSpace(s.Field)
		line := strings.TrimSpace(s.Value)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "fv", "vn", "version", "os", "md", "model", "ty", "product", "device", "hw":
		default:
			continue
		}
		conf := "medium"
		vr := false
		if k == "fv" || k == "version" || k == "vn" {
			vr = len(v) >= 2 && strings.ContainsAny(v, "0123456789.")
		}
		surf := "udp:5353/mdns"
		if svc != "" {
			surf += ":" + svc
		}
		f := store.Finding{
			Surface:           surf,
			VersionConfidence: conf,
			EvidenceKind:      "mdns_txt:" + k,
			EvidenceDigest:    digestEvidence(line),
			VulnReady:         vr,
		}
		switch k {
		case "os":
			f.ProductGuess = v
		case "fv", "vn", "version":
			f.VersionGuess = v
		default:
			f.ProductGuess = v
		}
		*out = append(*out, f)
	}
}

func appendHTTPExtractFindings(rec *Record, out *[]store.Finding) {
	for _, s := range rec.Signals {
		if s.Source != "http_extract" || strings.TrimSpace(s.Value) == "" {
			continue
		}
		p, ok := ParseHTTPExtractPayload(s.Value)
		if !ok {
			continue
		}
		surf := strings.TrimSpace(s.Field)
		if surf == "" {
			surf = "tcp/http"
		}
		conf := strings.TrimSpace(p.Conf)
		if conf == "" {
			conf = "low"
		}
		vr := conf == "high" && strings.TrimSpace(p.Version) != ""
		evk := "http_" + strings.TrimSpace(p.Kind)
		if p.Path != "" {
			evk += ":" + p.Path
		}
		*out = append(*out, store.Finding{
			Surface:           surf,
			VendorGuess:       "",
			ProductGuess:      strings.TrimSpace(p.Product),
			VersionGuess:      strings.TrimSpace(p.Version),
			VersionConfidence: conf,
			EvidenceKind:      evk,
			EvidenceDigest:    digestEvidence(strings.TrimSpace(p.Evidence)),
			VulnReady:         vr,
		})
	}
}

func appendTLSWeakFindings(rec *Record, out *[]store.Finding) {
	for _, s := range rec.Signals {
		if s.Source != "tls_cert" || strings.TrimSpace(s.Value) == "" {
			continue
		}
		surf := "tcp:443/tls"
		if strings.Contains(s.Field, "8443") {
			surf = "tcp:8443/tls"
		}
		v := strings.TrimSpace(s.Value)
		*out = append(*out, store.Finding{
			Surface:           surf,
			ProductGuess:      v,
			VersionConfidence: "low",
			EvidenceKind:      "tls_cert:" + s.Field,
			EvidenceDigest:    digestEvidence(v),
			VulnReady:         false,
		})
	}
}

func appendSSHFindings(rec *Record, out *[]store.Finding) {
	for _, sig := range rec.Signals {
		if sig.Source != "ssh_banner" || strings.TrimSpace(sig.Value) == "" {
			continue
		}
		ver := ""
		if m := reOpenSSHVer.FindStringSubmatch(sig.Value); len(m) > 1 {
			ver = strings.TrimSpace(m[1])
		}
		conf := "low"
		vr := false
		if ver != "" {
			conf = "high"
			vr = true
		}
		v := sig.Value
		if len(v) > 256 {
			v = v[:256]
		}
		*out = append(*out, store.Finding{
			Surface:           "tcp:22/ssh",
			ProductGuess:      "OpenSSH",
			VersionGuess:      ver,
			VersionConfidence: conf,
			EvidenceKind:      "ssh_banner",
			EvidenceDigest:    digestEvidence(v),
			VulnReady:         vr,
		})
		break
	}
}

func digestEvidence(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16])
}

func appendNmapFindings(rec *Record, out *[]store.Finding) {
	for _, s := range rec.Signals {
		if s.Source != "nmap" || !strings.HasPrefix(s.Field, "service:") || strings.TrimSpace(s.Value) == "" {
			continue
		}
		var p NmapServicePayload
		if err := json.Unmarshal([]byte(s.Value), &p); err != nil {
			continue
		}
		proto := strings.TrimSpace(p.Proto)
		port := strings.TrimSpace(p.Port)
		if proto == "" || port == "" {
			continue
		}
		name := strings.TrimSpace(p.Name)
		surf := proto + ":" + port
		if name != "" {
			surf += "/" + name
		}
		prod := strings.TrimSpace(p.Product)
		ver := strings.TrimSpace(p.Version)
		extra := strings.TrimSpace(p.Extrainfo)
		evText := strings.TrimSpace(strings.Join([]string{prod, ver, extra}, " "))
		conf := "low"
		vr := false
		if ver != "" && len(ver) >= 2 && strings.ContainsAny(ver, "0123456789") {
			conf = "medium"
			vr = true
			if prod != "" {
				conf = "high"
			}
		} else if prod != "" {
			conf = "low"
		}
		if evText != "" {
			*out = append(*out, store.Finding{
				Surface:           surf + "/nmap",
				ProductGuess:      prod,
				VersionGuess:      ver,
				VersionConfidence: conf,
				EvidenceKind:      "nmap_service",
				EvidenceDigest:    digestEvidence(evText + "|" + s.Field),
				VulnReady:         vr,
			})
		}
		for id, txt := range p.Scripts {
			txt = strings.TrimSpace(txt)
			if txt == "" {
				continue
			}
			pg := txt
			if len(pg) > 140 {
				pg = pg[:137] + "…"
			}
			*out = append(*out, store.Finding{
				Surface:           surf + "/nmap_script:" + id,
				ProductGuess:      pg,
				VersionConfidence: "low",
				EvidenceKind:      "nmap_script:" + id,
				EvidenceDigest:    digestEvidence(id + "|" + txt),
				VulnReady:         false,
			})
		}
	}
}

func appendRTSPFindings(rec *Record, out *[]store.Finding) {
	for _, s := range rec.Signals {
		if s.Source != "rtsp_banner" || strings.TrimSpace(s.Value) == "" {
			continue
		}
		port := strings.TrimPrefix(s.Field, "port_")
		if port == "" || port == s.Field {
			port = "554"
		}
		v := strings.TrimSpace(s.Value)
		*out = append(*out, store.Finding{
			Surface:           "tcp:" + port + "/rtsp",
			ProductGuess:      v,
			VersionConfidence: "low",
			EvidenceKind:      "rtsp_server_banner",
			EvidenceDigest:    digestEvidence(v),
			VulnReady:         false,
		})
	}
}
