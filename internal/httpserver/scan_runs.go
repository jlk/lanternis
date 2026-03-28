package httpserver

import "net/http"

func (s *Server) handleScanRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	runs, err := s.store.ListRecentScanRuns(r.Context(), 25)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}
