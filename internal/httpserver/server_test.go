package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jlk/lanternis/internal/discovery"
	"github.com/jlk/lanternis/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
		_ = os.Remove(dbPath)
	})
	logger := log.New(io.Discard, "", 0)
	return New(logger, st, discovery.NewScanner()), st
}

func TestScanStartRequiresCSRF(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","mode":"normal"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestScanStartWithCSRFTokenAccepted(t *testing.T) {
	srv, _ := newTestServer(t)

	// Step 1: get csrf cookie + token.
	csrfReq := httptest.NewRequest(http.MethodGet, "/api/csrf", nil)
	csrfRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(csrfRec, csrfReq)
	if csrfRec.Code != http.StatusOK {
		t.Fatalf("csrf endpoint failed: %d", csrfRec.Code)
	}

	var csrfResp map[string]string
	if err := json.Unmarshal(csrfRec.Body.Bytes(), &csrfResp); err != nil {
		t.Fatalf("decode csrf response: %v", err)
	}
	token := csrfResp["csrf_token"]
	if token == "" {
		t.Fatal("csrf token missing")
	}
	cookies := csrfRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("csrf cookie missing")
	}

	// Step 2: start scan with valid token pair.
	startReq := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","mode":"normal","concurrency":1}`))
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("X-CSRF-Token", token)
	startReq.AddCookie(cookies[0])
	startRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", startRec.Code, startRec.Body.String())
	}
}

func TestDuplicateScanStartReturnsConflict(t *testing.T) {
	srv, _ := newTestServer(t)
	token, cookie := csrfTokenAndCookie(t, srv)

	start := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"192.168.1.0/24","mode":"normal","concurrency":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", token)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	first := start()
	if first.Code != http.StatusAccepted {
		t.Fatalf("first start expected 202, got %d", first.Code)
	}

	second := start()
	if second.Code != http.StatusConflict {
		t.Fatalf("second start expected 409, got %d body=%s", second.Code, second.Body.String())
	}

	// Best-effort cleanup: cancel running scan.
	cancelReq := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	cancelReq.Header.Set("X-CSRF-Token", token)
	cancelReq.AddCookie(cookie)
	cancelRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(cancelRec, cancelReq)
	if cancelRec.Code != http.StatusOK {
		t.Fatalf("cancel expected 200, got %d body=%s", cancelRec.Code, cancelRec.Body.String())
	}

	// Give scanner goroutine a short window to settle.
	time.Sleep(100 * time.Millisecond)
}

func csrfTokenAndCookie(t *testing.T, srv *Server) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/csrf", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("csrf endpoint failed: %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode csrf: %v", err)
	}
	token := body["csrf_token"]
	if token == "" {
		t.Fatal("csrf token missing")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("csrf cookie missing")
	}
	return token, cookies[0]
}
