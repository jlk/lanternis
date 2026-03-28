package httpserver

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

func (s *Server) handleHostDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		writeErr(w, http.StatusBadRequest, errors.New("ip query parameter required"))
		return
	}
	if net.ParseIP(ip) == nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid ip"))
		return
	}
	host, err := s.store.GetHost(r.Context(), ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if host == nil {
		writeErr(w, http.StatusNotFound, errors.New("host not found"))
		return
	}
	hist, err := s.store.HostScanHistory(r.Context(), ip, 25)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host":         host,
		"scan_history": hist,
	})
}
