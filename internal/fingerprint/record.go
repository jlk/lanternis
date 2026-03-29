// Package fingerprint derives L1–L4 device identity from stored hints and optional probes.
package fingerprint

// Record is persisted in hosts.fingerprint_blob (JSON).
type Record struct {
	SchemaVersion int `json:"schema_version"`

	// LadderMax is the highest level (0–4) supported by current evidence (see FINGERPRINT-PLAN.md).
	LadderMax int `json:"ladder_max"`

	Manufacturer    string `json:"manufacturer,omitempty"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	Serial          string `json:"serial,omitempty"`

	// DeviceClass is an L2-style role guess (printer, camera, router, …) from fused hints.
	DeviceClass string `json:"device_class,omitempty"`

	// OSFamily / OSDetail are best-effort from banners (SSH, HTTP Server, SSDP) and optionally SMB.
	OSFamily string `json:"os_family,omitempty"` // linux | windows | darwin | freebsd | openbsd | embedded | unknown
	OSDetail string `json:"os_detail,omitempty"` // human-readable, includes evidence class in parentheses when weak
	// OSConflict is true when independent high-confidence hints disagree on OS family.
	OSConflict bool `json:"os_conflict,omitempty"`

	Signals []Signal `json:"signals,omitempty"`
	Summary string   `json:"summary,omitempty"`
}

// Signal is one piece of evidence backing the record.
type Signal struct {
	Source string `json:"source"` // oui, upnp_xml, http_title, http_server, tls_cert, ssh_banner, mdns_name, ptr, ssdp_st, ssdp_server, device_class, mdns_txt, os_ssh, os_http, os_ssdp, os_smb, os_rdp, os_tcp_stack, os_mdns_txt, os_upnp_text
	Field  string `json:"field,omitempty"`
	Value  string `json:"value,omitempty"`
}
