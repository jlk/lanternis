package fingerprint

import (
	"encoding/json"
	"testing"
)

func TestVendorFromRecord(t *testing.T) {
	t.Parallel()
	if got := VendorFromRecord(nil); got != "" {
		t.Fatalf("nil: got %q", got)
	}
	if got := VendorFromRecord(&Record{Manufacturer: "  Contoso  "}); got != "Contoso" {
		t.Fatalf("manufacturer: got %q", got)
	}
	if got := VendorFromRecord(&Record{
		Signals: []Signal{{Source: "oui", Value: " IEEE Vendor "}},
	}); got != "IEEE Vendor" {
		t.Fatalf("oui: got %q", got)
	}
	// Manufacturer wins over OUI.
	if got := VendorFromRecord(&Record{
		Manufacturer: "UPnP Name",
		Signals:      []Signal{{Source: "oui", Value: "OUI Name"}},
	}); got != "UPnP Name" {
		t.Fatalf("precedence: got %q", got)
	}
}

func TestVendorFromJSON(t *testing.T) {
	t.Parallel()
	if got := VendorFromJSON(nil); got != "" {
		t.Fatalf("nil blob: got %q", got)
	}
	if got := VendorFromJSON(json.RawMessage(`not json`)); got != "" {
		t.Fatalf("invalid json: got %q", got)
	}
	raw := json.RawMessage(`{"manufacturer":"X","signals":[{"source":"oui","value":"Y"}]}`)
	if got := VendorFromJSON(raw); got != "X" {
		t.Fatalf("json: got %q", got)
	}
}
