package fingerprint

import (
	"encoding/json"
	"testing"
)

func TestDeviceClassLabelFromLLMKey(t *testing.T) {
	if l, ok := DeviceClassLabelFromLLMKey("media"); !ok || l == "" {
		t.Fatalf("media: %q %v", l, ok)
	}
	if _, ok := DeviceClassLabelFromLLMKey("nope"); ok {
		t.Fatal("expected false")
	}
}

func TestApplyWebLLMStructured(t *testing.T) {
	rec := &Record{LadderMax: 1}
	ApplyWebLLMStructured(rec, "Google LLC", "media", "linux", "high")
	if rec.Manufacturer != "Google LLC" {
		t.Fatalf("manufacturer %q", rec.Manufacturer)
	}
	if want := classLabels["media"]; rec.DeviceClass != want {
		t.Fatalf("class %q want %q", rec.DeviceClass, want)
	}
	if rec.OSFamily != OSFamilyLinux {
		t.Fatalf("os %q", rec.OSFamily)
	}
}

func TestApplyWebLLMStructuredDoesNotOverwrite(t *testing.T) {
	rec := &Record{Manufacturer: "UPnP", DeviceClass: "Printer or scanner", OSFamily: OSFamilyWindows}
	ApplyWebLLMStructured(rec, "Other", "router", "linux", "low")
	if rec.Manufacturer != "UPnP" || rec.DeviceClass != "Printer or scanner" || rec.OSFamily != OSFamilyWindows {
		t.Fatalf("should keep protocol fields: m=%q class=%q os=%q", rec.Manufacturer, rec.DeviceClass, rec.OSFamily)
	}
}

func TestMergeWebLLMFieldsFromPrevious(t *testing.T) {
	prev := &Record{
		SchemaVersion: 1,
		LadderMax:     2,
		Signals: []Signal{
			{Source: "web_llm", Field: "manufacturer", Value: "Sony"},
			{Source: "web_llm", Field: "device_class", Value: "media"},
		},
	}
	b, err := json.Marshal(prev)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Record{SchemaVersion: 1, LadderMax: 2}
	MergeWebLLMFieldsFromPrevious(rec, b)
	if rec.Manufacturer != "Sony" || rec.DeviceClass != classLabels["media"] {
		t.Fatalf("got m=%q class=%q", rec.Manufacturer, rec.DeviceClass)
	}
}

func TestStripWebLLMSignals(t *testing.T) {
	s := []Signal{{Source: "oui", Value: "x"}, {Source: "web_llm", Field: "manufacturer", Value: "y"}}
	out := StripWebLLMSignals(s)
	if len(out) != 1 || out[0].Source != "oui" {
		t.Fatalf("%+v", out)
	}
}
