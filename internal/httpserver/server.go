package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/jlk/lanternis/internal/audit"
	"github.com/jlk/lanternis/internal/discovery"
	"github.com/jlk/lanternis/internal/store"
)

type Server struct {
	logger  *log.Logger
	store   *store.Store
	scanner *discovery.Scanner
	mux     *http.ServeMux
}

func New(logger *log.Logger, st *store.Store, scanner *discovery.Scanner) *Server {
	s := &Server{
		logger:  logger,
		store:   st,
		scanner: scanner,
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/api/csrf", s.handleCSRF)
	s.mux.HandleFunc("/api/hosts", s.handleHosts)
	s.mux.HandleFunc("/api/scan/status", s.handleScanStatus)
	s.mux.HandleFunc("/api/scan/start", s.requireCSRF(s.handleScanStart))
	s.mux.HandleFunc("/api/scan/cancel", s.requireCSRF(s.handleScanCancel))
}

func (s *Server) handleHome(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Lanternis</title></head>
<body>
  <main>
    <h1>Lanternis</h1>
    <p>Local network scanner (M1 scaffold).</p>
    <p>Use the JSON endpoints for now:</p>
    <ul>
      <li><code>GET /api/csrf</code></li>
      <li><code>GET /api/scan/status</code></li>
      <li><code>POST /api/scan/start</code></li>
      <li><code>POST /api/scan/cancel</code></li>
      <li><code>GET /api/hosts</code></li>
    </ul>
  </main>
</body>
</html>`))
}

func (s *Server) handleCSRF(w http.ResponseWriter, _ *http.Request) {
	token := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.scanner.Status())
}

type startReq struct {
	CIDR        string `json:"cidr"`
	Mode        string `json:"mode"`
	Concurrency int    `json:"concurrency"`
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req startReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.CIDR == "" {
		req.CIDR = "192.168.1.0/24"
	}
	if req.Mode == "" {
		req.Mode = "normal"
	}
	if req.Concurrency == 0 {
		req.Concurrency = 32
	}

	runID, err := s.scanner.Start(r.Context(), req.CIDR, req.Concurrency, func(result discovery.Result) error {
		return s.store.UpsertHost(context.Background(), store.Host{
			IP:           result.IP,
			Reachability: result.Reachability,
			Label:        "",
			Confidence:   result.Confidence,
			LastSeen:     result.ObservedAt,
		})
	})
	if err != nil {
		if err.Error() == "scan already running" {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	dbRunID, err := s.store.InsertScanRun(r.Context(), req.Mode)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = audit.Append(r.Context(), s.store, "scan_started", map[string]any{
		"scan_id": dbRunID,
		"cidr":    req.CIDR,
		"mode":    req.Mode,
	})

	go s.watchAndFinalize(dbRunID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"scan_id": runID,
		"status":  s.scanner.Status(),
	})
}

func (s *Server) watchAndFinalize(dbRunID int64) {
	for {
		st := s.scanner.Status()
		if !st.Running {
			cancelled := st.ScanPhase == "cancelled"
			_ = s.store.MarkScanEnded(context.Background(), dbRunID, cancelled)
			_ = audit.Append(context.Background(), s.store, "scan_finished", map[string]any{
				"scan_id":    dbRunID,
				"phase":      st.ScanPhase,
				"completed":  st.Completed,
				"total":      st.Total,
				"cancelled":  cancelled,
				"finishedAt": time.Now().UTC().Format(time.RFC3339Nano),
			})
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *Server) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	ok := s.scanner.Cancel()
	if !ok {
		writeErr(w, http.StatusConflict, errors.New("no scan is running"))
		return
	}
	_ = audit.Append(r.Context(), s.store, "scan_cancel_requested", map[string]any{
		"at": time.Now().UTC().Format(time.RFC3339Nano),
	})
	writeJSON(w, http.StatusOK, map[string]any{"cancel_requested": true})
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "http://127.0.0.1:8080" && origin != "http://localhost:8080" {
			writeErr(w, http.StatusForbidden, errors.New("invalid origin"))
			return
		}
		cookie, err := r.Cookie("csrf_token")
		if err != nil {
			writeErr(w, http.StatusForbidden, errors.New("csrf cookie missing"))
			return
		}
		header := r.Header.Get("X-CSRF-Token")
		if header == "" || header != cookie.Value {
			writeErr(w, http.StatusForbidden, errors.New("csrf token mismatch"))
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func randomToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "fallback-csrf-token"
	}
	return hex.EncodeToString(buf)
}
