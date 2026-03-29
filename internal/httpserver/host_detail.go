package httpserver

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/jlk/lanternis/internal/fingerprint"
	"github.com/jlk/lanternis/internal/store"
)

// hostJSON is the API shape for one host row, including derived vendor and device class.
type hostJSON struct {
	store.Host
	Vendor      string `json:"vendor,omitempty"`
	DeviceClass string `json:"device_class,omitempty"`
}

func newHostJSON(h store.Host) hostJSON {
	v, dc := fingerprint.ListExtrasFromFingerprint(h.Fingerprint)
	return hostJSON{
		Host:        h,
		Vendor:      v,
		DeviceClass: dc,
	}
}

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
	findings, err := s.store.ListFindingsByHost(r.Context(), ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	inferences := fingerprint.InferencesFromFingerprintBlob(host.Fingerprint)
	if inferences == nil {
		inferences = []fingerprint.NameInference{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host":         newHostJSON(*host),
		"findings":     findings,
		"inferences":   inferences,
		"scan_history": hist,
	})
}
