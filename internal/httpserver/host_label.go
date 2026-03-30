package httpserver

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/jlk/lanternis/internal/audit"
	"github.com/jlk/lanternis/internal/fingerprint"
)

type hostLabelFromHintReq struct {
	IP              string `json:"ip"`
	InferenceIndex  int    `json:"inference_index"`
}

func (s *Server) handleHostLabelFromHint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	ok, err := s.store.FirstRunComplete(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden, errors.New("complete first-run setup first"))
		return
	}
	var req hostLabelFromHintReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return
	}
	ip := strings.TrimSpace(req.IP)
	if ip == "" || net.ParseIP(ip) == nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid ip"))
		return
	}
	if req.InferenceIndex < 0 {
		writeErr(w, http.StatusBadRequest, errors.New("invalid inference_index"))
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
	inferences := fingerprint.InferencesFromFingerprintBlob(host.Fingerprint)
	if req.InferenceIndex >= len(inferences) {
		writeErr(w, http.StatusBadRequest, errors.New("inference_index out of range"))
		return
	}
	inf := inferences[req.InferenceIndex]
	label := fingerprint.InventoryLabelFromInference(inf)
	if strings.TrimSpace(label) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("empty label from inference"))
		return
	}
	conf := fingerprint.HostConfidenceFromInference(inf)
	if err := s.store.UpdateHostLabelAndConfidence(r.Context(), ip, label, conf); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = audit.Append(r.Context(), s.store, "host_label_from_hint", map[string]any{
		"ip":             ip,
		"source":         inf.Source,
		"inference_kind": inf.Kind,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"label":      label,
		"confidence": conf,
	})
}
