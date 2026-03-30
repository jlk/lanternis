package webenrich

import (
	"strings"

	"github.com/jlk/lanternis/internal/fingerprint"
)

func stripWebLLM(in []fingerprint.NameInference) []fingerprint.NameInference {
	if len(in) == 0 {
		return in
	}
	out := make([]fingerprint.NameInference, 0, len(in))
	for _, x := range in {
		if x.Source == "web_llm" {
			continue
		}
		out = append(out, x)
	}
	return out
}

func firstOUIFromRecord(rec *fingerprint.Record) string {
	if rec == nil {
		return ""
	}
	for _, sig := range rec.Signals {
		if sig.Source == "oui" && strings.TrimSpace(sig.Value) != "" {
			return strings.TrimSpace(sig.Value)
		}
	}
	return ""
}

func buildPrompt(haystack, deviceClass, ouiVendor string) string {
	var b strings.Builder
	b.WriteString("You help identify consumer home-network devices from hostname and mDNS fragments only.\n")
	b.WriteString("Reply with a single JSON object and nothing else. Keys:\n")
	b.WriteString("- guess (string): short product name or empty if unknown.\n")
	b.WriteString("- confidence (\"low\"|\"medium\"|\"high\").\n")
	b.WriteString("- note (string): one short sentence; no PII.\n")
	b.WriteString("- vendor (string): brand/manufacturer if reasonably inferable, else \"\".\n")
	b.WriteString("- device_class_key (string): one of printer|camera|nas|router|home_automation|media|game_console|mobile|server|audio|computer|network|iot — or \"\" if unknown.\n")
	b.WriteString("- os_family (string): one of linux|windows|darwin|embedded — or \"\" if unknown (do not guess OS from vendor alone).\n")
	b.WriteString("Do not repeat long strings from the hints. Do not invent a specific CVE or firmware.\n\n")
	if deviceClass != "" {
		b.WriteString("Inferred device class (heuristic): ")
		b.WriteString(deviceClass)
		b.WriteByte('\n')
	}
	if ouiVendor != "" {
		b.WriteString("NIC vendor (OUI): ")
		b.WriteString(ouiVendor)
		b.WriteByte('\n')
	}
	b.WriteString("Name hints (lowercase, truncated):\n")
	b.WriteString(haystack)
	return b.String()
}
