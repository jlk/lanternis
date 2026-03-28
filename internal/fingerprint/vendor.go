package fingerprint

import (
	"encoding/json"
	"strings"
)

// VendorFromRecord returns a display vendor name derived from fingerprint evidence:
// the device manufacturer when present (e.g. UPnP description), otherwise the IEEE OUI
// vendor string from the MAC prefix signal when available.
func VendorFromRecord(rec *Record) string {
	if rec == nil {
		return ""
	}
	if s := strings.TrimSpace(rec.Manufacturer); s != "" {
		return s
	}
	for _, sig := range rec.Signals {
		if sig.Source == "oui" && strings.TrimSpace(sig.Value) != "" {
			return strings.TrimSpace(sig.Value)
		}
	}
	return ""
}

// VendorFromJSON parses a hosts.fingerprint_blob payload and returns VendorFromRecord.
func VendorFromJSON(blob json.RawMessage) string {
	if len(blob) == 0 {
		return ""
	}
	var rec Record
	if err := json.Unmarshal(blob, &rec); err != nil {
		return ""
	}
	return VendorFromRecord(&rec)
}
