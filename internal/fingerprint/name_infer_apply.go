package fingerprint

import "strings"

// ApplyNameInferences fills rec.Inferences from local rules and optional user aliases.
// It does not change DisplayLabel, ladder, or findings—hypotheses are secondary in UI/API.
func ApplyNameInferences(rec *Record, hints map[string]any, aliases *DeviceAliasesFile) {
	if rec == nil {
		return
	}
	var out []NameInference
	if aliases != nil {
		out = append(out, matchUserMacAliases(hints, aliases)...)
	}
	hay := buildNameHaystack(rec, hints)
	out = append(out, matchUserHostnameAliases(hay, aliases)...)
	out = append(out, matchLocalNameRules(hay)...)
	rec.Inferences = dedupeInferences(out)
}

func matchUserMacAliases(hints map[string]any, aliases *DeviceAliasesFile) []NameInference {
	if aliases == nil || len(aliases.MacPrefixes) == 0 {
		return nil
	}
	arp, ok := hints["arp"].(map[string]any)
	if !ok {
		return nil
	}
	mac, _ := arp["mac"].(string)
	mac = normalizeMAC(mac)
	if mac == "" {
		return nil
	}
	var out []NameInference
	for prefix, label := range aliases.MacPrefixes {
		p := normalizeMAC(prefix)
		if p == "" || strings.TrimSpace(label) == "" {
			continue
		}
		if strings.HasPrefix(mac, p) {
			out = append(out, NameInference{
				Source:     "user_alias_mac",
				Kind:       "user_label",
				Confidence: "high",
				Input:      strings.TrimSpace(prefix),
				Text:       strings.TrimSpace(label),
			})
		}
	}
	return out
}

func matchUserHostnameAliases(hay string, aliases *DeviceAliasesFile) []NameInference {
	if aliases == nil || hay == "" || len(aliases.HostnameSubstrings) == 0 {
		return nil
	}
	var out []NameInference
	for needle, label := range aliases.HostnameSubstrings {
		n := strings.TrimSpace(strings.ToLower(needle))
		if n == "" || strings.TrimSpace(label) == "" {
			continue
		}
		if strings.Contains(hay, n) {
			out = append(out, NameInference{
				Source:     "user_alias_hostname",
				Kind:       "user_label",
				Confidence: "high",
				Input:      strings.TrimSpace(needle),
				Text:       strings.TrimSpace(label),
			})
		}
	}
	return out
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	return s
}

func buildNameHaystack(rec *Record, hints map[string]any) string {
	var parts []string
	if rec != nil {
		for _, sig := range rec.Signals {
			switch sig.Source {
			case "ptr", "mdns_name":
				parts = append(parts, sig.Value)
			case "upnp_xml":
				if strings.EqualFold(sig.Field, "friendlyName") {
					parts = append(parts, sig.Value)
				}
			case "http_title":
				parts = append(parts, sig.Value)
			}
		}
		parts = append(parts, rec.Model, rec.Manufacturer, rec.Summary, rec.DeviceClass)
	}
	if mdns, ok := hints["mdns"].(map[string]any); ok {
		for _, n := range stringSliceFromAny(mdns["names"]) {
			parts = append(parts, n)
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

// NameHaystackForEnrichment is the same lowercase string used for local name rules (hostnames, titles, model strings — not IP addresses).
func NameHaystackForEnrichment(rec *Record, hints map[string]any) string {
	return buildNameHaystack(rec, hints)
}

func matchLocalNameRules(hay string) []NameInference {
	if hay == "" {
		return nil
	}
	var out []NameInference
	for _, r := range builtinNameRules {
		if strings.Contains(hay, r.pattern) {
			out = append(out, NameInference{
				Source:     "local_rule",
				Kind:       r.kind,
				Confidence: r.confidence,
				Input:      r.pattern,
				Text:       r.text,
				RuleID:     r.ruleID,
			})
		}
	}
	return out
}

func dedupeInferences(in []NameInference) []NameInference {
	seen := make(map[string]struct{})
	var out []NameInference
	for _, x := range in {
		k := x.Source + "|" + x.RuleID + "|" + strings.ToLower(x.Input) + "|" + x.Text
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, x)
	}
	return out
}
