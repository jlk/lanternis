package fingerprint

import (
	"encoding/json"
	"strings"
)

// IdentityProvenance explains which evidence channel primarily backs list-style identity fields.
// It is for UX transparency; it does not replace the evidence chain in Record.Signals.
type IdentityProvenance struct {
	Manufacturer string `json:"manufacturer_source,omitempty"`
	DeviceClass  string `json:"device_class_source,omitempty"`
	OS           string `json:"os_source,omitempty"`
}

var osEvidencePriority = []string{
	"os_ssh", "os_smb", "os_rdp", "os_http", "os_ssdp", "os_upnp_text", "os_mdns_txt", "os_tcp_stack",
}

// IdentityProvenanceFromBlob parses hosts.fingerprint_blob and returns provenance hints.
func IdentityProvenanceFromBlob(blob json.RawMessage) IdentityProvenance {
	if len(blob) == 0 {
		return IdentityProvenance{}
	}
	var rec Record
	if err := json.Unmarshal(blob, &rec); err != nil {
		return IdentityProvenance{}
	}
	return IdentityProvenanceFromRecord(&rec)
}

// IdentityProvenanceFromRecord derives provenance from a fused record.
func IdentityProvenanceFromRecord(rec *Record) IdentityProvenance {
	if rec == nil {
		return IdentityProvenance{}
	}
	var p IdentityProvenance
	p.Manufacturer = provenanceManufacturer(rec)
	p.DeviceClass = provenanceDeviceClass(rec)
	p.OS = provenanceOS(rec)
	return p
}

func provenanceManufacturer(rec *Record) string {
	man := strings.TrimSpace(rec.Manufacturer)
	if man != "" {
		if signalValueMatch(rec, "upnp_xml", "manufacturer", man) {
			return "upnp_device_xml"
		}
		if webLLMFieldMatches(rec, "manufacturer", man) {
			return "web_llm"
		}
		return "unknown"
	}
	if hasSignalSource(rec, "oui") {
		return "ieee_oui_mac_prefix"
	}
	return ""
}

func provenanceDeviceClass(rec *Record) string {
	if strings.TrimSpace(rec.DeviceClass) == "" {
		return ""
	}
	if hasSignalSourceField(rec, "device_class", "score") {
		return "ports_passive_banners"
	}
	if webLLMDeviceClassMatches(rec) {
		return "web_llm"
	}
	return "unknown"
}

func provenanceOS(rec *Record) string {
	if rec.OSConflict {
		return "conflict"
	}
	f := strings.TrimSpace(rec.OSFamily)
	if f == "" || f == OSFamilyUnknown {
		return ""
	}
	det := strings.TrimSpace(rec.OSDetail)
	if strings.Contains(det, "LLM") {
		return "web_llm"
	}
	return primaryOSSignalSource(rec)
}

func signalValueMatch(rec *Record, source, field, want string) bool {
	want = strings.TrimSpace(want)
	for _, s := range rec.Signals {
		if s.Source == source && s.Field == field && strings.TrimSpace(s.Value) == want {
			return true
		}
	}
	return false
}

func webLLMFieldMatches(rec *Record, field, want string) bool {
	want = strings.TrimSpace(want)
	for _, s := range rec.Signals {
		if s.Source == "web_llm" && s.Field == field && strings.TrimSpace(s.Value) == want {
			return true
		}
	}
	return false
}

func webLLMDeviceClassMatches(rec *Record) bool {
	want := strings.TrimSpace(rec.DeviceClass)
	for _, s := range rec.Signals {
		if s.Source != "web_llm" || s.Field != "device_class" {
			continue
		}
		if label, ok := DeviceClassLabelFromLLMKey(s.Value); ok && label == want {
			return true
		}
	}
	return false
}

func hasSignalSource(rec *Record, source string) bool {
	for _, s := range rec.Signals {
		if s.Source == source {
			return true
		}
	}
	return false
}

func hasSignalSourceField(rec *Record, source, field string) bool {
	for _, s := range rec.Signals {
		if s.Source == source && s.Field == field {
			return true
		}
	}
	return false
}

func primaryOSSignalSource(rec *Record) string {
	seen := make(map[string]bool)
	for _, s := range rec.Signals {
		if strings.HasPrefix(s.Source, "os_") {
			seen[s.Source] = true
		}
	}
	for _, pref := range osEvidencePriority {
		if seen[pref] {
			return pref
		}
	}
	for _, s := range rec.Signals {
		if strings.HasPrefix(s.Source, "os_") {
			return s.Source
		}
	}
	return "fused"
}
