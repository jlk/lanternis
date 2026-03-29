package fingerprint

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jlk/lanternis/internal/store"
)

type fpFixture struct {
	Name  string         `json:"name"`
	Host  fixtureHost    `json:"host"`
	Hints map[string]any `json:"hints"`
	Want  fpFixtureWant  `json:"want"`
}

type fixtureHost struct {
	IP        string   `json:"ip"`
	OpenPorts []string `json:"open_ports"`
}

type fpFixtureWant struct {
	DeviceClass   string `json:"device_class"`
	ModelContains string `json:"model_contains,omitempty"`
	ServiceType   string `json:"service_type,omitempty"`
}

func TestFingerprintFixtures(t *testing.T) {
	t.Parallel()

	oldPTR := LookupPTRFunc
	LookupPTRFunc = func(ctx context.Context, ip string) ([]string, error) { return nil, nil }
	t.Cleanup(func() { LookupPTRFunc = oldPTR })

	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "testdata")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("no fixtures in %s", dir)
	}

	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		e := e
		t.Run(e.Name(), func(t *testing.T) {
			t.Parallel()

			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			var fx fpFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			h := store.Host{
				IP:        fx.Host.IP,
				OpenPorts: fx.Host.OpenPorts,
				LastSeen:  time.Now().UTC(),
			}
			rec, err := Build(t.Context(), h, fx.Hints, nil, nil)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if rec == nil {
				t.Fatalf("expected record, got nil")
			}
			if got := strings.TrimSpace(rec.DeviceClass); got != strings.TrimSpace(fx.Want.DeviceClass) {
				t.Fatalf("device_class: got %q want %q (signals=%+v)", got, fx.Want.DeviceClass, rec.Signals)
			}
			if fx.Want.ModelContains != "" && !strings.Contains(strings.ToLower(rec.Model), strings.ToLower(fx.Want.ModelContains)) {
				t.Fatalf("model: got %q; want contains %q", rec.Model, fx.Want.ModelContains)
			}
			if fx.Want.ServiceType != "" {
				var saw bool
				for _, s := range rec.Signals {
					if s.Source == "mdns_service" && strings.Contains(strings.ToLower(s.Value), strings.ToLower(fx.Want.ServiceType)) {
						saw = true
						break
					}
				}
				if !saw {
					t.Fatalf("expected mdns_service %q in signals: %+v", fx.Want.ServiceType, rec.Signals)
				}
			}
		})
	}
}
