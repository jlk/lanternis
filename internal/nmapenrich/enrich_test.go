package nmapenrich

import (
	"context"
	"os"
	"testing"

	"github.com/jlk/lanternis/internal/fingerprint"
)

func TestEnrichInjectsXMLSignals(t *testing.T) {
	saved := runNmap
	defer func() { runNmap = saved }()
	runNmap = func(ctx context.Context, name string, arg ...string) ([]byte, error) {
		return os.ReadFile("testdata/minimal.xml")
	}
	rec := &fingerprint.Record{}
	err := Enrich(context.Background(), rec, "192.168.1.1", []string{"80", "22"}, nil, "/fake/nmap", DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Signals) < 2 {
		t.Fatalf("expected nmap signals, got %+v", rec.Signals)
	}
	var saw80 bool
	for _, s := range rec.Signals {
		if s.Source == "nmap" && s.Field == "service:tcp:80" {
			saw80 = true
			break
		}
	}
	if !saw80 {
		t.Fatalf("missing service:tcp:80 in %#v", rec.Signals)
	}
}
