package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jlk/lanternis/internal/audit"
	"github.com/jlk/lanternis/internal/store"
)

type webEnrichmentReq struct {
	Enabled           bool   `json:"enabled"`
	Provider          string `json:"provider"`
	OpenAIAPIKey      string `json:"openai_api_key"`
	AnthropicAPIKey   string `json:"anthropic_api_key"`
	ClearOpenAIKey    bool   `json:"clear_openai_key"`
	ClearAnthropicKey bool   `json:"clear_anthropic_key"`
}

func (s *Server) handleWebEnrichmentSettings(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.FirstRunComplete(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden, errors.New("complete first-run setup first"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		en, err := s.store.WebEnrichmentEnabled(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		prov, err := s.store.WebEnrichmentProvider(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		openOK, err := s.store.OpenAIAPIKeyConfigured(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		anOK, err := s.store.AnthropicAPIKeyConfigured(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":                     en,
			"provider":                    prov,
			"openai_api_key_configured":   openOK,
			"anthropic_api_key_configured": anOK,
		})
	case http.MethodPost:
		var req webEnrichmentReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
			return
		}
		up := store.WebEnrichmentUpdate{
			Enabled:           req.Enabled,
			Provider:          strings.TrimSpace(req.Provider),
			OpenAIKey:         req.OpenAIAPIKey,
			AnthropicKey:      req.AnthropicAPIKey,
			ClearOpenAIKey:    req.ClearOpenAIKey,
			ClearAnthropicKey: req.ClearAnthropicKey,
		}
		if err := s.store.SetWebEnrichment(r.Context(), up); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		_ = audit.Append(r.Context(), s.store, "web_enrichment_settings_updated", map[string]any{
			"enabled":   req.Enabled,
			"provider":  strings.TrimSpace(req.Provider),
			"cleared_o": req.ClearOpenAIKey,
			"cleared_a": req.ClearAnthropicKey,
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}
