package httpserver

import (
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) handleScanDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	diff, err := s.store.BuildScanDiff(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func (s *Server) handleScanDiffExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	diff, err := s.store.BuildScanDiff(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	wrap := map[string]any{
		"export_schema_version": 1,
		"generated_at_utc":      time.Now().UTC().Format(time.RFC3339Nano),
		"note":                  "Local diff export. IPs included for your LAN review only.",
		"diff":                  diff,
	}
	b, err := json.MarshalIndent(wrap, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="lanternis-scan-diff.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
