package fingerprint

import (
	"strings"

	"github.com/jlk/lanternis/internal/store"
)

// ProbeContext carries active probe strings used only for classification (not full signal list).
type ProbeContext struct {
	PTRNames      []string
	HTTPTitle80   string
	HTTPServer80  string
	HTTPTitle443  string
	HTTPServer443 string
	TLSCN         string
	SSHBanner     string
	MDNSServices  []MDNSServiceHint
}

type MDNSServiceHint struct {
	Type string
	Port int
	TXT  []string
}

// classPriority breaks ties when two buckets reach the same score (first wins).
var classPriority = []string{
	"printer", "camera", "nas", "router", "home_automation", "media",
	"game_console", "mobile", "server", "audio", "computer", "network", "iot",
}

var classLabels = map[string]string{
	"printer":         "Printer or scanner",
	"camera":          "IP camera or NVR",
	"nas":             "NAS or file server",
	"router":          "Router or gateway",
	"home_automation": "Home automation hub",
	"media":           "TV, streaming, or cast device",
	"game_console":    "Game console",
	"mobile":          "Phone or tablet",
	"server":          "Server (SSH / multi-service)",
	"audio":           "Speaker or audio gear",
	"computer":        "PC or Mac",
	"network":         "Network infrastructure",
	"iot":             "Generic IoT / gadget",
}

const minDeviceClassScore = 3

// ClassifyDevice fuses ports, passive hints, PTR names, and banner text into DeviceClass and extra signals.
func ClassifyDevice(rec *Record, h store.Host, hints map[string]any, p ProbeContext) {
	if rec == nil {
		return
	}
	scores := make(map[string]int)
	ports := portSet(h.OpenPorts)

	httpBlob := strings.ToLower(strings.Join([]string{
		p.HTTPTitle80, p.HTTPServer80, p.HTTPTitle443, p.HTTPServer443,
	}, " "))
	tlsSSH := strings.ToLower(p.TLSCN + " " + p.SSHBanner)
	if strings.Contains(tlsSSH, "openssh") {
		scores["server"] += 1
	}

	// --- Strong port profiles ---
	if ports["631"] || ports["9100"] {
		scores["printer"] += 5
	}
	if ports["554"] || ports["8554"] || ports["37777"] || ports["34567"] {
		scores["camera"] += 5
	}
	if ports["8123"] {
		scores["home_automation"] += 6
	}
	if ports["1883"] || ports["8883"] {
		scores["home_automation"] += 2
	}
	if ports["5000"] && (strings.Contains(httpBlob, "plex") || strings.Contains(httpBlob, "synology") || strings.Contains(tlsSSH, "synology")) {
		scores["nas"] += 3
	}
	if ports["445"] && ports["139"] {
		scores["computer"] += 2
	}
	if ports["22"] && (len(h.OpenPorts) >= 4 || strings.Contains(p.SSHBanner, "OpenSSH")) {
		scores["server"] += 2
	}

	// --- SSDP ST / USN tokens (passive) ---
	if ssdp, ok := hints["ssdp"].(map[string]any); ok {
		if srv, ok := ssdp["server"].(string); ok {
			s := strings.ToLower(srv)
			rec.Signals = append(rec.Signals, Signal{Source: "ssdp_server", Field: "server", Value: truncate(srv, 160)})
			if strings.Contains(s, "roku") || strings.Contains(s, "chromecast") || strings.Contains(s, "airplay") {
				scores["media"] += 3
			}
			if strings.Contains(s, "synology") || strings.Contains(s, "qnap") || strings.Contains(s, "netgear") {
				scores["nas"] += 2
			}
		}
		for _, st := range stringSliceFromAny(ssdp["st_types"]) {
			st = strings.TrimSpace(st)
			if st == "" {
				continue
			}
			rec.Signals = append(rec.Signals, Signal{Source: "ssdp_st", Field: "st", Value: truncate(st, 160)})
			stl := strings.ToLower(st)
			switch {
			case strings.Contains(stl, "printer"), strings.Contains(stl, "print"):
				scores["printer"] += 4
			case strings.Contains(stl, "scanner"):
				scores["printer"] += 3
			case strings.Contains(stl, "mediarenderer"), strings.Contains(stl, "mediaserver"),
				strings.Contains(stl, "digitalmediarenderer"), strings.Contains(stl, "dmr"):
				scores["media"] += 3
			case strings.Contains(stl, "internetgatewaydevice"), strings.Contains(stl, "wandevice"),
				strings.Contains(stl, "wancommoninterfaceconfig"), strings.Contains(stl, "lanhostconfigmanagement"):
				scores["router"] += 4
			case strings.Contains(stl, "binarylight"), strings.Contains(stl, "dimmer"), strings.Contains(stl, "hue"):
				scores["home_automation"] += 2
			case strings.Contains(stl, "camera"), strings.Contains(stl, "digitalsecurity"):
				scores["camera"] += 3
			}
		}
	}

	// --- mDNS names ---
	if mdns, ok := hints["mdns"].(map[string]any); ok {
		for _, n := range stringSliceFromAny(mdns["names"]) {
			nl := strings.ToLower(strings.TrimSpace(n))
			if nl == "" {
				continue
			}
			switch {
			case strings.Contains(nl, "chromecast"), strings.Contains(nl, "googlecast"):
				scores["media"] += 3
			case strings.Contains(nl, "homepod"), strings.Contains(nl, "sonos"), strings.Contains(nl, "heos"):
				scores["audio"] += 3
			case strings.Contains(nl, "iphone"), strings.Contains(nl, "ipad"), strings.Contains(nl, "android"):
				scores["mobile"] += 2
			case strings.Contains(nl, "hap._tcp"), strings.Contains(nl, "homekit"):
				scores["home_automation"] += 2
			}
		}
	}

	// --- mDNS service types / TXT ---
	for _, s := range p.MDNSServices {
		ty := strings.ToLower(strings.TrimSpace(s.Type))
		if ty == "" {
			continue
		}
		switch {
		case strings.Contains(ty, "_ipp._tcp"), strings.Contains(ty, "_printer._tcp"), strings.Contains(ty, "_pdl-datastream._tcp"):
			scores["printer"] += 6
		case strings.Contains(ty, "_hap._tcp"):
			scores["home_automation"] += 5
		case strings.Contains(ty, "_googlecast._tcp"), strings.Contains(ty, "_airplay._tcp"):
			scores["media"] += 6
		case strings.Contains(ty, "_raop._tcp"), strings.Contains(ty, "_sonos._tcp"):
			scores["audio"] += 6
		case strings.Contains(ty, "_smb._tcp"), strings.Contains(ty, "_workstation._tcp"):
			scores["computer"] += 3
			scores["nas"] += 1
		}
		if len(s.TXT) > 0 {
			txt := strings.ToLower(strings.Join(s.TXT, " "))
			if strings.Contains(txt, "home-assistant") || strings.Contains(txt, "hass") {
				scores["home_automation"] += 3
			}
			if strings.Contains(txt, "chromecast") || strings.Contains(txt, "googlecast") {
				scores["media"] += 2
			}
			if strings.Contains(txt, "airplay") {
				scores["media"] += 1
				scores["audio"] += 1
			}
		}
	}

	// --- PTR names ---
	for _, n := range p.PTRNames {
		nl := strings.ToLower(n)
		switch {
		case strings.Contains(nl, "printer"), strings.Contains(nl, "ipp"), strings.Contains(nl, "cups"):
			scores["printer"] += 3
		case strings.Contains(nl, "router"), strings.Contains(nl, "gateway"), strings.HasPrefix(nl, "gw."),
			strings.Contains(nl, ".gw."), strings.Contains(nl, "firewall"):
			scores["router"] += 3
		case strings.Contains(nl, "cam"), strings.Contains(nl, "nvr"), strings.Contains(nl, "dvr"), strings.Contains(nl, "ipcam"):
			scores["camera"] += 3
		case strings.Contains(nl, "nas"), strings.Contains(nl, "diskstation"), strings.Contains(nl, "synology"), strings.Contains(nl, "qnap"):
			scores["nas"] += 3
		case strings.Contains(nl, "xbox"), strings.Contains(nl, "playstation"), strings.Contains(nl, "nintendo"):
			scores["game_console"] += 4
		case strings.Contains(nl, "iphone"), strings.Contains(nl, "ipad"), strings.Contains(nl, "android"):
			scores["mobile"] += 2
		case strings.Contains(nl, "switch"), strings.Contains(nl, "ap."), strings.Contains(nl, "wifi"):
			scores["network"] += 2
		}
	}

	// --- HTTP(S) bodies and Server headers ---
	if strings.Contains(httpBlob, "home assistant") || strings.Contains(httpBlob, "hassio") {
		scores["home_automation"] += 5
	}
	if strings.Contains(httpBlob, "synology") || strings.Contains(httpBlob, "diskstation") || strings.Contains(httpBlob, "dsm ") {
		scores["nas"] += 4
	}
	if strings.Contains(httpBlob, "qnap") || strings.Contains(httpBlob, "turbo nas") {
		scores["nas"] += 4
	}
	if strings.Contains(httpBlob, "webmin") {
		scores["server"] += 2
	}
	if strings.Contains(httpBlob, "openwrt") || strings.Contains(httpBlob, "dd-wrt") || strings.Contains(httpBlob, "tomato") || strings.Contains(httpBlob, "mikrotik") {
		scores["router"] += 4
	}
	if strings.Contains(httpBlob, "ui.com") || strings.Contains(httpBlob, "unifi") {
		scores["network"] += 3
	}

	// --- TLS CN / SAN snippet ---
	tlsLow := strings.ToLower(p.TLSCN)
	if strings.Contains(tlsLow, "router") || strings.Contains(tlsLow, "gateway") || strings.Contains(tlsLow, "fw.") {
		scores["router"] += 2
	}
	if strings.Contains(tlsLow, "synology") || strings.Contains(tlsLow, "qnap") || strings.Contains(tlsLow, "nas.") {
		scores["nas"] += 3
	}

	if label, score := pickClass(scores); label != "" {
		rec.DeviceClass = label
		rec.Signals = append(rec.Signals, Signal{
			Source: "device_class", Field: "score", Value: truncate(scoreBucketKey(scores, score), 80),
		})
		if rec.LadderMax < 2 {
			rec.LadderMax = 2
		}
	}
}

func pickClass(scores map[string]int) (label string, best int) {
	best = 0
	for _, v := range scores {
		if v > best {
			best = v
		}
	}
	if best < minDeviceClassScore {
		return "", 0
	}
	for _, k := range classPriority {
		if scores[k] == best {
			return classLabels[k], best
		}
	}
	return "", 0
}

// scoreBucketKey returns the winning bucket name for the evidence signal (debug).
func scoreBucketKey(scores map[string]int, val int) string {
	for _, k := range classPriority {
		if scores[k] == val {
			return k
		}
	}
	return ""
}
