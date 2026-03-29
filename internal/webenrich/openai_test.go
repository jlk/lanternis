package webenrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jlk/lanternis/internal/fingerprint"
)

func TestParseEnrichmentJSON(t *testing.T) {
	g, c, n, err := parseEnrichmentJSON(`{"guess":"x","confidence":"HIGH","note":"y"}`, "def")
	if err != nil || g != "x" || c != "high" || n != "y" {
		t.Fatalf("got %q %q %q err %v", g, c, n, err)
	}
	g, c, n, err = parseEnrichmentJSON(`{"guess":"","confidence":"low","note":""}`, "fallback")
	if err != nil || n != "fallback" {
		t.Fatalf("got %q %q %q err %v", g, c, n, err)
	}
	_, _, _, err = parseEnrichmentJSON("```json\n{\"guess\":\"\",\"confidence\":\"low\",\"note\":\"nope\"}\n```", "x")
	if err != nil {
		t.Fatal(err)
	}
}

func TestStripWebLLM(t *testing.T) {
	in := []fingerprint.NameInference{
		{Source: "local_rule", Text: "a"},
		{Source: "web_llm", Text: "b"},
	}
	out := stripWebLLM(in)
	if len(out) != 1 || out[0].Source != "local_rule" {
		t.Fatalf("%+v", out)
	}
}

func TestEnrichRecordEmptyHaystack(t *testing.T) {
	rec := &fingerprint.Record{Signals: []fingerprint.Signal{{Source: "ptr", Value: "ab"}}}
	if err := EnrichRecord(context.Background(), rec, nil, ProviderOpenAI, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if len(rec.Inferences) != 0 {
		t.Fatalf("expected skip short haystack")
	}
}

func TestEnrichRecordIntegrationHTTPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"guess\":\"Chromecast Ultra\",\"confidence\":\"medium\",\"note\":\"Name token\"}"}}]}`))
	}))
	defer ts.Close()

	old := openAIURL
	openAIURL = ts.URL + "/v1/chat/completions"
	defer func() { openAIURL = old }()

	rec := &fingerprint.Record{
		Signals: []fingerprint.Signal{{Source: "mdns_name", Value: "living-room-chromecast.local"}},
	}
	if err := EnrichRecord(context.Background(), rec, nil, ProviderOpenAI, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if len(rec.Inferences) != 1 || rec.Inferences[0].Source != "web_llm" {
		t.Fatalf("%+v", rec.Inferences)
	}
	if rec.Inferences[0].Input != "openai" {
		t.Fatalf("input %q", rec.Inferences[0].Input)
	}
	if !strings.Contains(rec.Inferences[0].Text, "Chromecast") {
		t.Fatalf("text %q", rec.Inferences[0].Text)
	}
}

func TestEnrichRecordAnthropicIntegrationHTTPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" {
			http.Error(w, "no key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"guess\":\"Apple TV\",\"confidence\":\"high\",\"note\":\"mdns\"}"}]}`))
	}))
	defer ts.Close()

	old := anthropicMessagesURL
	anthropicMessagesURL = ts.URL + "/v1/messages"
	defer func() { anthropicMessagesURL = old }()

	rec := &fingerprint.Record{
		Signals: []fingerprint.Signal{{Source: "mdns_name", Value: "appletv-living.local"}},
	}
	if err := EnrichRecord(context.Background(), rec, nil, ProviderAnthropic, "sk-ant-test"); err != nil {
		t.Fatal(err)
	}
	if len(rec.Inferences) != 1 || rec.Inferences[0].Input != "claude" {
		t.Fatalf("%+v", rec.Inferences)
	}
	if !strings.Contains(rec.Inferences[0].Text, "Apple TV") {
		t.Fatalf("text %q", rec.Inferences[0].Text)
	}
}
