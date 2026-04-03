package fingerprint

import (
	"encoding/json"
	"testing"

	"github.com/jlk/lanternis/internal/store"
)

func TestFindingsFromRecordNmapVulnReady(t *testing.T) {
	pl := NmapServicePayload{
		Proto:   "tcp",
		Port:    "443",
		Name:    "https",
		Product: "nginx",
		Version: "1.22.1",
	}
	raw, err := json.Marshal(pl)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Record{
		Signals: []Signal{
			{Source: "nmap", Field: "service:tcp:443", Value: string(raw)},
		},
	}
	out := FindingsFromRecord(rec)
	var svc *store.Finding
	for i := range out {
		if out[i].EvidenceKind == "nmap_service" {
			svc = &out[i]
			break
		}
	}
	if svc == nil {
		t.Fatalf("expected nmap_service finding, got %#v", out)
	}
	if !svc.VulnReady {
		t.Fatal("expected vuln_ready for versioned nmap service")
	}
	if svc.VersionConfidence != "high" {
		t.Fatalf("confidence: %s", svc.VersionConfidence)
	}
}

func TestFindingsFromRecordNmapScriptNotVulnReady(t *testing.T) {
	pl := NmapServicePayload{
		Proto: "tcp",
		Port:  "80",
		Name:  "http",
		Scripts: map[string]string{
			"http-title": "Camera admin",
		},
	}
	raw, _ := json.Marshal(pl)
	rec := &Record{
		Signals: []Signal{{Source: "nmap", Field: "service:tcp:80", Value: string(raw)}},
	}
	out := FindingsFromRecord(rec)
	for _, f := range out {
		if f.EvidenceKind == "nmap_script:http-title" {
			if f.VulnReady {
				t.Fatal("script finding should not be vuln_ready")
			}
			return
		}
	}
	t.Fatal("missing script finding")
}
