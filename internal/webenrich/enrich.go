package webenrich

import (
	"context"
	"strings"

	"github.com/jlk/lanternis/internal/fingerprint"
)

// Provider IDs stored in app_kv and sent to EnrichRecord.
const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
)

// EnrichRecord appends at most one web_llm NameInference when the API returns a usable guess.
// provider must be ProviderOpenAI or ProviderAnthropic (empty treated as OpenAI).
// Errors are non-fatal (caller ignores).
func EnrichRecord(ctx context.Context, rec *fingerprint.Record, hints map[string]any, provider, apiKey string) error {
	if rec == nil || strings.TrimSpace(apiKey) == "" {
		return nil
	}
	hay := fingerprint.NameHaystackForEnrichment(rec, hints)
	if len(strings.TrimSpace(hay)) < 4 {
		return nil
	}
	if len(hay) > 600 {
		hay = hay[:597] + "…"
	}
	oui := firstOUIFromRecord(rec)
	dc := strings.TrimSpace(rec.DeviceClass)
	prompt := buildPrompt(hay, dc, oui)

	p := normalizeProvider(provider)
	var body string
	var err error
	switch p {
	case ProviderAnthropic:
		body, err = callAnthropic(ctx, apiKey, prompt)
	default:
		body, err = callOpenAI(ctx, apiKey, prompt)
	}
	if err != nil {
		return err
	}
	guess, conf, note, err := parseEnrichmentJSON(body, defaultNoteForProvider(p))
	if err != nil || strings.TrimSpace(guess) == "" {
		return err
	}
	rec.Inferences = stripWebLLM(rec.Inferences)
	rec.Inferences = append(rec.Inferences, fingerprint.NameInference{
		Source:     "web_llm",
		Kind:       "product_hint",
		Confidence: conf,
		Input:      inferenceInputTag(p),
		Text:       strings.TrimSpace(guess) + " — " + strings.TrimSpace(note),
		RuleID:     "web_llm_v1",
	})
	return nil
}

func normalizeProvider(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ProviderAnthropic:
		return ProviderAnthropic
	default:
		return ProviderOpenAI
	}
}

func inferenceInputTag(p string) string {
	if p == ProviderAnthropic {
		return "claude"
	}
	return "openai"
}

func defaultNoteForProvider(p string) string {
	if p == ProviderAnthropic {
		return "Claude suggestion (opt-in)."
	}
	return "OpenAI suggestion (opt-in)."
}
