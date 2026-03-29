package fingerprint

import (
	"encoding/json"
	"testing"
)

func TestApplyNameInferencesChromecast(t *testing.T) {
	rec := &Record{
		Signals: []Signal{{Source: "mdns_name", Field: "name", Value: "living-room-chromecast.local"}},
	}
	ApplyNameInferences(rec, map[string]any{}, nil)
	if len(rec.Inferences) < 1 {
		t.Fatalf("expected inference, got %+v", rec.Inferences)
	}
	if rec.Inferences[0].Source != "local_rule" || rec.Inferences[0].RuleID != "cast_chromecast" {
		t.Fatalf("unexpected: %+v", rec.Inferences[0])
	}
}

func TestApplyNameInferencesUserMac(t *testing.T) {
	rec := &Record{Signals: []Signal{{Source: "oui", Value: "Acme"}}}
	hints := map[string]any{"arp": map[string]any{"mac": "aa:bb:cc:dd:ee:01"}}
	aliases := &DeviceAliasesFile{
		MacPrefixes: map[string]string{"aa:bb:cc": "Office switch"},
	}
	ApplyNameInferences(rec, hints, aliases)
	if len(rec.Inferences) != 1 || rec.Inferences[0].Source != "user_alias_mac" {
		t.Fatalf("got %+v", rec.Inferences)
	}
	if rec.Inferences[0].Text != "Office switch" {
		t.Fatalf("text %q", rec.Inferences[0].Text)
	}
}

func TestApplyNameUserHostname(t *testing.T) {
	rec := &Record{Signals: []Signal{{Source: "mdns_name", Value: "kitchen-widget.local"}}}
	hints := map[string]any{}
	aliases := &DeviceAliasesFile{
		HostnameSubstrings: map[string]string{"kitchen-widget": "Kid tablet"},
	}
	ApplyNameInferences(rec, hints, aliases)
	found := false
	for _, x := range rec.Inferences {
		if x.Source == "user_alias_hostname" && x.Text == "Kid tablet" {
			found = true
		}
	}
	if !found {
		t.Fatalf("got %+v", rec.Inferences)
	}
}

func TestInferencesFromFingerprintBlob(t *testing.T) {
	rec := &Record{
		SchemaVersion: 1,
		LadderMax:     2,
		Inferences: []NameInference{
			{Source: "local_rule", Kind: "family", Confidence: "low", Input: "x", Text: "y", RuleID: "z"},
		},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	out := InferencesFromFingerprintBlob(b)
	if len(out) != 1 || out[0].Text != "y" {
		t.Fatalf("got %+v", out)
	}
}

func TestBuiltinNameRulesCoverage(t *testing.T) {
	if len(builtinNameRules) < 200 {
		t.Fatalf("expected large curated rule set (>=200), got %d", len(builtinNameRules))
	}
}

func TestLoadDeviceAliasesMissing(t *testing.T) {
	f, err := LoadDeviceAliases("/nonexistent/lanternis/device_aliases_does_not_exist.json")
	if err != nil {
		t.Fatal(err)
	}
	if f == nil || len(f.MacPrefixes) != 0 {
		t.Fatalf("got %+v", f)
	}
}
