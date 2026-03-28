package fingerprint

import (
	"context"
	"testing"
	"time"

	"github.com/jlk/lanternis/internal/store"
)

func TestClassifyPrinterPorts(t *testing.T) {
	t.Parallel()
	rec := &Record{SchemaVersion: 1}
	h := store.Host{OpenPorts: []string{"631", "80"}}
	ClassifyDevice(rec, h, map[string]any{}, ProbeContext{})
	if rec.DeviceClass != classLabels["printer"] {
		t.Fatalf("device class: got %q want %q", rec.DeviceClass, classLabels["printer"])
	}
}

func TestClassifySSDPGateway(t *testing.T) {
	t.Parallel()
	rec := &Record{SchemaVersion: 1}
	h := store.Host{OpenPorts: []string{"80"}}
	hints := map[string]any{
		"ssdp": map[string]any{
			"st_types": []any{"urn:schemas-upnp-org:device:InternetGatewayDevice:1"},
		},
	}
	ClassifyDevice(rec, h, hints, ProbeContext{})
	if rec.DeviceClass != classLabels["router"] {
		t.Fatalf("device class: got %q want %q", rec.DeviceClass, classLabels["router"])
	}
}

func TestClassifyPTRCamera(t *testing.T) {
	t.Parallel()
	rec := &Record{SchemaVersion: 1}
	h := store.Host{OpenPorts: []string{"80"}}
	ClassifyDevice(rec, h, map[string]any{}, ProbeContext{
		PTRNames: []string{"hikvision-cam-01.lan"},
	})
	if rec.DeviceClass != classLabels["camera"] {
		t.Fatalf("device class: got %q want %q", rec.DeviceClass, classLabels["camera"])
	}
}

func TestClassifyHomeAssistant(t *testing.T) {
	t.Parallel()
	rec := &Record{SchemaVersion: 1}
	h := store.Host{OpenPorts: []string{"8123"}}
	ClassifyDevice(rec, h, map[string]any{}, ProbeContext{})
	if rec.DeviceClass != classLabels["home_automation"] {
		t.Fatalf("device class: got %q want %q", rec.DeviceClass, classLabels["home_automation"])
	}
}

func TestBuildAddsPTRSignal(t *testing.T) {
	ctx := t.Context()
	old := LookupPTRFunc
	LookupPTRFunc = func(ctx context.Context, ip string) ([]string, error) {
		return []string{"gw.home.lan."}, nil
	}
	t.Cleanup(func() { LookupPTRFunc = old })

	h := store.Host{
		IP:           "10.0.0.1",
		Reachability: "reachable",
		LastSeen:     time.Now().UTC(),
	}
	rec, err := Build(ctx, h, map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("expected record with PTR")
	}
	var sawPTR bool
	for _, s := range rec.Signals {
		if s.Source == "ptr" && s.Value != "" {
			sawPTR = true
			break
		}
	}
	if !sawPTR {
		t.Fatalf("expected ptr signal: %+v", rec.Signals)
	}
}
