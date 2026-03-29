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

type builtinRule struct {
	pattern    string
	kind       string
	confidence string
	text       string
	ruleID     string
}

var builtinNameRules = []builtinRule{
	{"chromecast", "family", "medium", "Likely Google Cast / Chromecast or Google TV stack (from name token).", "cast_chromecast"},
	{"googlecast", "family", "medium", "Likely Google Cast device (mDNS service token).", "cast_googlecast"},
	{"_googlecast._tcp", "family", "medium", "Likely Google Cast (mDNS service type).", "cast_srv_googlecast"},
	{"roku", "family", "medium", "Likely Roku or Roku-based TV/streaming (from name token).", "stream_roku"},
	{"echo-dot", "family", "medium", "Likely Amazon Echo Dot (from name token).", "amz_echo_dot"},
	{"echo-", "family", "low", "Possibly Amazon Echo-family speaker (from name token).", "amz_echo"},
	{"amazon-", "family", "low", "Possibly Amazon Echo / Fire or Ring-class device (generic hostname prefix).", "amz_prefix"},
	{"meross", "family", "medium", "Likely Meross smart plug or switch (from name token).", "iot_meross"},
	{"tasmota", "family", "high", "Likely Tasmota firmware device (from name token).", "iot_tasmota"},
	{"esp_", "family", "low", "Possibly Espressif / ESPHome-class device (from hostname pattern).", "iot_esp"},
	{"esphome", "family", "high", "Likely ESPHome (from name token).", "iot_esphome"},
	{"homebridge", "family", "high", "Likely Homebridge hub or accessory name.", "hap_homebridge"},
	{"unifi", "family", "medium", "Likely Ubiquiti UniFi gear (from name token).", "net_unifi"},
	{"ubnt", "family", "medium", "Likely Ubiquiti device (from name token).", "net_ubnt"},
	{"synology", "family", "high", "Likely Synology NAS or router (from name token).", "nas_synology"},
	{"qnap", "family", "high", "Likely QNAP NAS (from name token).", "nas_qnap"},
	{"nas", "family", "low", "Possibly a NAS or file-server style hostname.", "nas_generic"},
	{"raspberrypi", "family", "medium", "Likely Raspberry Pi (default hostname style).", "pi_raspberry"},
	{"raspberry", "family", "low", "Possibly Raspberry Pi (from name token).", "pi_raspberry_loose"},
	{"plex", "family", "medium", "Likely Plex media server (from name token).", "media_plex"},
	{"fronius", "family", "high", "Likely Fronius solar inverter or gateway (from name token).", "energy_fronius"},
	{"hue", "family", "medium", "Likely Philips Hue bridge or accessory (from name token).", "hap_hue"},
	{"philips-hue", "family", "high", "Likely Philips Hue (from name token).", "hap_philips_hue"},
	{"nest-", "family", "low", "Possibly Google Nest-class device (from name prefix).", "nest_prefix"},
	{"lutron", "family", "medium", "Likely Lutron Caséta or RA2 gear (from name token).", "iot_lutron"},
	{"shelly", "family", "medium", "Likely Shelly Wi-Fi device (from name token).", "iot_shelly"},
	{"tuya", "family", "low", "Possibly Tuya-class smart device (from name token).", "iot_tuya"},
	{"wiz_", "family", "medium", "Likely WiZ connected light (from hostname prefix).", "iot_wiz"},
	{"august", "family", "medium", "Possibly August or Yale smart lock bridge (from name token).", "lock_august"},
	{"ring-", "family", "low", "Possibly Ring camera or doorbell (from name prefix).", "cam_ring"},
	{"wyze", "family", "medium", "Likely Wyze camera or plug (from name token).", "iot_wyze"},
	{"eero", "family", "high", "Likely eero mesh Wi-Fi (from name token).", "net_eero"},
	{"nestwifi", "family", "medium", "Likely Google Nest Wi-Fi (from name token).", "net_nestwifi"},
	{"brw", "family", "low", "Possibly a Brother network printer (common mDNS hostname prefix).", "printer_brother_brw"},
	{"sonos", "family", "high", "Likely Sonos speaker (from name token).", "audio_sonos"},
	{"airplay", "family", "medium", "Likely AirPlay-capable device (from name or service hint).", "media_airplay"},
}
