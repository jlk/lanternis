package fingerprint

import (
	"encoding/json"
	"strings"
)

// DeviceClassLabelFromLLMKey maps a canonical class key (printer, router, …) to the same
// display string ClassifyDevice uses. Unknown keys return false.
func DeviceClassLabelFromLLMKey(key string) (label string, ok bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return "", false
	}
	l, ok := classLabels[k]
	return l, ok
}

// StripWebLLMSignals removes prior web_llm evidence rows so a new enrichment can replace them.
func StripWebLLMSignals(signals []Signal) []Signal {
	if len(signals) == 0 {
		return signals
	}
	out := make([]Signal, 0, len(signals))
	for _, s := range signals {
		if s.Source == "web_llm" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func hasWebLLMSignalField(signals []Signal, field string) bool {
	for _, s := range signals {
		if s.Source == "web_llm" && s.Field == field {
			return true
		}
	}
	return false
}

func appendWebLLMSignal(signals []Signal, sig Signal) []Signal {
	if hasWebLLMSignalField(signals, sig.Field) {
		return signals
	}
	return append(signals, sig)
}

// MergeWebLLMFieldsFromPrevious copies manufacturer / device class / OS from a prior fingerprint_blob
// when the current Build left those fields empty. Call only when skipping a new LLM request.
func MergeWebLLMFieldsFromPrevious(rec *Record, prevBlob []byte) {
	if rec == nil || len(prevBlob) == 0 {
		return
	}
	var prev Record
	if err := json.Unmarshal(prevBlob, &prev); err != nil {
		return
	}
	for _, sig := range prev.Signals {
		if sig.Source != "web_llm" {
			continue
		}
		applyWebLLMSignalMerge(rec, sig)
	}
}

// ApplyWebLLMStructured applies optional vendor / class / OS from a new LLM response.
// It only fills fields that are still empty (or OS unknown) so protocol evidence wins.
func ApplyWebLLMStructured(rec *Record, vendor, deviceClassKey, osFamily string, confidence string) {
	if rec == nil {
		return
	}
	confidence = strings.TrimSpace(confidence)
	if confidence == "" {
		confidence = "low"
	}
	v := strings.TrimSpace(vendor)
	if v != "" && strings.TrimSpace(rec.Manufacturer) == "" && !hasStrongManufacturerProtocolEvidence(rec) {
		rec.Manufacturer = truncate(v, 120)
		rec.Signals = appendWebLLMSignal(rec.Signals, Signal{Source: "web_llm", Field: "manufacturer", Value: rec.Manufacturer})
	}
	if label, ok := DeviceClassLabelFromLLMKey(deviceClassKey); ok && strings.TrimSpace(rec.DeviceClass) == "" {
		rec.DeviceClass = label
		key := strings.ToLower(strings.TrimSpace(deviceClassKey))
		rec.Signals = appendWebLLMSignal(rec.Signals, Signal{Source: "web_llm", Field: "device_class", Value: key})
	}
	if okOS := normalizeLLMOSFamily(osFamily); okOS != "" && shouldApplyLLMOS(rec) {
		rec.OSFamily = okOS
		rec.OSDetail = "LLM suggestion from hostname hints (" + confidence + " confidence)"
		rec.Signals = appendWebLLMSignal(rec.Signals, Signal{Source: "web_llm", Field: "os_family", Value: okOS})
	}
}

func hasStrongManufacturerProtocolEvidence(rec *Record) bool {
	if rec == nil {
		return false
	}
	for _, s := range rec.Signals {
		if s.Source == "upnp_xml" && s.Field == "manufacturer" && strings.TrimSpace(s.Value) != "" {
			return true
		}
	}
	return false
}

func applyWebLLMSignalMerge(rec *Record, sig Signal) {
	v := strings.TrimSpace(sig.Value)
	if v == "" {
		return
	}
	switch sig.Field {
	case "manufacturer":
		if strings.TrimSpace(rec.Manufacturer) != "" || hasStrongManufacturerProtocolEvidence(rec) {
			return
		}
		rec.Manufacturer = truncate(v, 120)
		rec.Signals = appendWebLLMSignal(rec.Signals, Signal{Source: "web_llm", Field: "manufacturer", Value: rec.Manufacturer})
	case "device_class":
		if strings.TrimSpace(rec.DeviceClass) != "" {
			return
		}
		if label, ok := DeviceClassLabelFromLLMKey(v); ok {
			rec.DeviceClass = label
			rec.Signals = appendWebLLMSignal(rec.Signals, Signal{Source: "web_llm", Field: "device_class", Value: v})
		}
	case "os_family":
		if !shouldApplyLLMOS(rec) {
			return
		}
		if okOS := normalizeLLMOSFamily(v); okOS != "" {
			rec.OSFamily = okOS
			rec.OSDetail = "LLM suggestion (restored from prior scan)"
			rec.Signals = appendWebLLMSignal(rec.Signals, Signal{Source: "web_llm", Field: "os_family", Value: okOS})
		}
	}
}

func shouldApplyLLMOS(rec *Record) bool {
	if rec == nil {
		return false
	}
	if rec.OSConflict {
		return false
	}
	f := strings.TrimSpace(rec.OSFamily)
	return f == "" || f == OSFamilyUnknown
}

func normalizeLLMOSFamily(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case OSFamilyLinux, "debian", "ubuntu", "fedora", "raspbian":
		return OSFamilyLinux
	case OSFamilyWindows:
		return OSFamilyWindows
	case OSFamilyDarwin, "macos", "ios", "ipad", "iphone":
		return OSFamilyDarwin
	case OSFamilyFreeBSD:
		return OSFamilyFreeBSD
	case OSFamilyOpenBSD:
		return OSFamilyOpenBSD
	case OSFamilyNetBSD:
		return OSFamilyNetBSD
	case OSFamilyEmbedded:
		return OSFamilyEmbedded
	default:
		return ""
	}
}
