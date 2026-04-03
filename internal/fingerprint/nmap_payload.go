package fingerprint

// NmapServicePayload is JSON stored in Signal.Value when Source == "nmap" and Field starts with "service:".
type NmapServicePayload struct {
	Proto     string            `json:"proto"`
	Port      string            `json:"port"`
	Name      string            `json:"name"`
	Product   string            `json:"product"`
	Version   string            `json:"version"`
	Extrainfo string            `json:"extrainfo,omitempty"`
	Scripts   map[string]string `json:"scripts,omitempty"`
}
