package fingerprint

import (
	"testing"
)

func TestDisplayLabelPTRAndMDNS(t *testing.T) {
	t.Parallel()
	ip := "10.0.0.44"
	rec := &Record{
		SchemaVersion: 1,
		LadderMax:     2,
		Signals: []Signal{
			{Source: "ptr", Field: "name", Value: "livingroom-tv.home.lan"},
			{Source: "mdns_name", Field: "name", Value: "chromecast-ultra.local."},
		},
	}
	// Managed DNS (PTR) should beat a co-existing mDNS hostname when both look intentional.
	if got := DisplayLabel(rec, map[string]any{}, ip); got != "livingroom-tv" {
		t.Fatalf("ptr should win: got %q", got)
	}
}

func TestDisplayLabelPTRWhenNoMDNSName(t *testing.T) {
	t.Parallel()
	ip := "192.168.1.10"
	rec := &Record{
		Signals: []Signal{{Source: "ptr", Field: "name", Value: "router.lan"}},
	}
	if got := DisplayLabel(rec, map[string]any{}, ip); got != "router" {
		t.Fatalf("ptr: got %q", got)
	}
}

func TestDisplayLabelSkipsInAddrPTR(t *testing.T) {
	t.Parallel()
	rec := &Record{Signals: []Signal{{Source: "ptr", Field: "name", Value: "10.0.0.44.in-addr.arpa"}}}
	if got := DisplayLabel(rec, map[string]any{}, "10.0.0.44"); got != "10.0.0.44" {
		t.Fatalf("got %q want IP fallback", got)
	}
}

func TestDisplayLabelHintsOnly(t *testing.T) {
	t.Parallel()
	ip := "10.1.2.3"
	h := map[string]any{
		"mdns": map[string]any{
			"names": []any{"kitchen-speaker.local"},
		},
	}
	if got := DisplayLabel(nil, h, ip); got != "kitchen-speaker" {
		t.Fatalf("got %q", got)
	}
}

func TestDisplayLabelNilRecFallsBackToIP(t *testing.T) {
	t.Parallel()
	if got := DisplayLabel(nil, map[string]any{}, "192.168.1.12"); got != "192.168.1.12" {
		t.Fatalf("got %q", got)
	}
}

func TestDisplayLabelMDNSNamesAsString(t *testing.T) {
	t.Parallel()
	h := map[string]any{
		"mdns": map[string]any{"names": "office-tv.local"},
	}
	if got := DisplayLabel(nil, h, "192.168.1.12"); got != "office-tv" {
		t.Fatalf("got %q", got)
	}
}

func TestDisplayLabelServiceFN(t *testing.T) {
	t.Parallel()
	ip := "10.2.2.2"
	rec := &Record{LadderMax: 1}
	h := map[string]any{
		"mdns": map[string]any{
			"services": []any{
				map[string]any{
					"type": "_googlecast._tcp.local",
					"txt":  []any{"fn=Living Room TV", "md=Chromecast"},
				},
			},
		},
	}
	if got := DisplayLabel(rec, h, ip); got != "Living Room TV" {
		t.Fatalf("got %q", got)
	}
}

func TestDisplayLabelPTRBeatsOpaqueMDNSAndGenericUPnP(t *testing.T) {
	t.Parallel()
	ip := "192.168.1.23"
	rec := &Record{
		LadderMax:     4,
		Manufacturer:  "General",
		Model:         "IPC",
		DeviceClass:   "IP camera or NVR",
		SchemaVersion: 1,
		Signals: []Signal{
			{Source: "ptr", Field: "name", Value: "back-of-house-cam.mercer.jlk.dev"},
			{Source: "upnp_xml", Field: "modelDescription", Value: "General IPC"},
			{Source: "mdns_name", Field: "name", Value: "8h0823dpag23ed1.local"},
		},
	}
	h := map[string]any{
		"mdns": map[string]any{
			"names": []any{"8h0823dpag23ed1.local"},
		},
	}
	if got := DisplayLabel(rec, h, ip); got != "back-of-house-cam" {
		t.Fatalf("got %q want PTR short name", got)
	}
}

func TestDisplayLabelMDNSWhenNoPTR(t *testing.T) {
	t.Parallel()
	rec := &Record{
		Signals: []Signal{
			{Source: "mdns_name", Field: "name", Value: "chromecast-ultra.local."},
		},
	}
	if got := DisplayLabel(rec, map[string]any{}, "10.0.0.2"); got != "chromecast-ultra" {
		t.Fatalf("got %q", got)
	}
}

func TestInventoryLabelFromInference(t *testing.T) {
	t.Parallel()
	got := InventoryLabelFromInference(NameInference{Text: "Chromecast Ultra — optional note"})
	if got != "Chromecast Ultra" {
		t.Fatalf("got %q", got)
	}
	if InventoryLabelFromInference(NameInference{Text: "  "}) != "" {
		t.Fatal("expected empty")
	}
	if HostConfidenceFromInference(NameInference{Confidence: "bogus"}) != "medium" {
		t.Fatal("default confidence")
	}
	if HostConfidenceFromInference(NameInference{Confidence: "low"}) != "low" {
		t.Fatal("low")
	}
}
