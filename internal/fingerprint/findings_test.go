package fingerprint

import (
	"testing"

	"github.com/jlk/lanternis/internal/store"
)

func TestFindingsFromRecordNil(t *testing.T) {
	if fs := FindingsFromRecord(nil); fs != nil {
		t.Fatalf("expected nil, got %d", len(fs))
	}
}

func TestFindingsFromRecordUPnP(t *testing.T) {
	rec := &Record{
		Manufacturer:    "ACME",
		Model:           "Router 9000",
		FirmwareVersion: "1.2.3",
	}
	fs := FindingsFromRecord(rec)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Surface != "upnp/device" || f.VendorGuess != "ACME" || f.ProductGuess != "Router 9000" {
		t.Fatalf("unexpected: %+v", f)
	}
	if f.VersionGuess != "1.2.3" || f.VersionConfidence != "high" || !f.VulnReady {
		t.Fatalf("version/confidence: %+v", f)
	}
	if f.EvidenceKind != "upnp_device_xml" || len(f.EvidenceDigest) < 8 {
		t.Fatalf("evidence: %+v", f)
	}
}

func TestFindingsFromRecordSSH(t *testing.T) {
	rec := &Record{
		Signals: []Signal{
			{Source: "ssh_banner", Field: "line", Value: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"},
		},
	}
	fs := FindingsFromRecord(rec)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Surface != "tcp:22/ssh" || f.ProductGuess != "OpenSSH" {
		t.Fatalf("unexpected: %+v", f)
	}
	if f.VersionGuess != "9.2p1" || !f.VulnReady {
		t.Fatalf("version: %+v", f)
	}
}

func TestFindingsFromRecordUPnPAndSSH(t *testing.T) {
	rec := &Record{
		Manufacturer: "NASCo",
		Model:        "Box",
		Signals: []Signal{
			{Source: "ssh_banner", Value: "SSH-2.0-OpenSSH_8.4"},
		},
	}
	fs := FindingsFromRecord(rec)
	if len(fs) != 2 {
		t.Fatalf("expected 2, got %d: %+v", len(fs), fs)
	}
}

func TestFindingsFromRecordGranularUPnP(t *testing.T) {
	rec := &Record{
		Manufacturer: "ACME",
		Model:        "X",
		Signals: []Signal{
			{Source: "upnp_xml", Field: "manufacturer", Value: "ACME"},
			{Source: "upnp_xml", Field: "softwareVersion", Value: "9.9.9"},
		},
	}
	fs := FindingsFromRecord(rec)
	if len(fs) < 2 {
		t.Fatalf("expected granular UPnP findings, got %d %+v", len(fs), fs)
	}
}

func TestFindingsFromRecordHTTPExtract(t *testing.T) {
	js := `{"kind":"server","product":"nginx","version":"1.22.0","conf":"high","evidence":"nginx/1.22.0"}`
	rec := &Record{
		Signals: []Signal{{Source: "http_extract", Field: "tcp:80/http", Value: js}},
	}
	fs := FindingsFromRecord(rec)
	if len(fs) != 1 || !fs[0].VulnReady || fs[0].Surface != "tcp:80/http" {
		t.Fatalf("got %+v", fs)
	}
}

// Compile-time check: store.Finding shape used by API.
var _ = store.Finding{}
