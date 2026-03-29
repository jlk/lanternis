package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/jlk/lanternis/internal/store"
)

var reOpenSSHVer = regexp.MustCompile(`(?i)OpenSSH[_-]([0-9][0-9a-z._-]*)`)

// FindingsFromRecord derives vuln-oriented findings from a persisted fingerprint Record.
// Phase A: UPnP device fields and SSH banner (OpenSSH version) only; expand in Phase B.
func FindingsFromRecord(rec *Record) []store.Finding {
	if rec == nil {
		return nil
	}
	var out []store.Finding
	if strings.TrimSpace(rec.Manufacturer) != "" || strings.TrimSpace(rec.Model) != "" || strings.TrimSpace(rec.FirmwareVersion) != "" {
		conf := "low"
		vr := false
		if strings.TrimSpace(rec.FirmwareVersion) != "" {
			conf = "high"
			vr = true
		} else if strings.TrimSpace(rec.Manufacturer) != "" && strings.TrimSpace(rec.Model) != "" {
			conf = "medium"
		}
		ev := strings.TrimSpace(rec.Manufacturer + "|" + rec.Model + "|" + rec.FirmwareVersion)
		out = append(out, store.Finding{
			Surface:             "upnp/device",
			VendorGuess:         strings.TrimSpace(rec.Manufacturer),
			ProductGuess:        strings.TrimSpace(rec.Model),
			VersionGuess:        strings.TrimSpace(rec.FirmwareVersion),
			VersionConfidence:   conf,
			EvidenceKind:        "upnp_device_xml",
			EvidenceDigest:      digestEvidence(ev),
			VulnReady:           vr,
		})
	}
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
		out = append(out, store.Finding{
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
	return out
}

func digestEvidence(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16])
}
