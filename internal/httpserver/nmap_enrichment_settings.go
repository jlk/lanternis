package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"strings"

	"github.com/jlk/lanternis/internal/audit"
)

type nmapEnrichmentReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleNmapEnrichmentSettings(w http.ResponseWriter, r *http.Request) {
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
		en, err := s.store.NmapEnrichmentEnabled(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		_, nmapOK := exec.LookPath("nmap")
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      en,
			"nmap_on_path": nmapOK,
		})
	case http.MethodPost:
		var req nmapEnrichmentReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
			return
		}
		if err := s.store.SetNmapEnrichment(r.Context(), req.Enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		_ = audit.Append(r.Context(), s.store, "nmap_enrichment_settings_updated", map[string]any{
			"enabled": req.Enabled,
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

func nmapOnPath() bool {
	p, err := exec.LookPath("nmap")
	return err == nil && strings.TrimSpace(p) != ""
}
