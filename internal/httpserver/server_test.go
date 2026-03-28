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
	if err := st.CompleteFirstRun(context.Background(), "10.0.0.0/30"); err != nil {
		t.Fatalf("complete first run: %v", err)
	}
	logger := log.New(io.Discard, "", 0)
	return New(logger, st, discovery.NewScanner(), Config{DBPath: dbPath, Version: "test"}), st
}

func newTestServerWithoutFirstRun(t *testing.T) (*Server, *store.Store) {
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
	return New(logger, st, discovery.NewScanner(), Config{DBPath: dbPath, Version: "test"}), st
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

func TestScanStartRejectsCSRFTokenMismatch(t *testing.T) {
	srv, _ := newTestServer(t)
	_, cookie := csrfTokenAndCookie(t, srv)

	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","mode":"normal","concurrency":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "definitely-not-the-cookie-token")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanStartRejectsInvalidOrigin(t *testing.T) {
	srv, _ := newTestServer(t)
	token, cookie := csrfTokenAndCookie(t, srv)

	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","mode":"normal","concurrency":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.Header.Set("Origin", "http://evil.example")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanStartRejectsInvalidCIDR(t *testing.T) {
	srv, _ := newTestServer(t)
	token, cookie := csrfTokenAndCookie(t, srv)

	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"not-a-cidr","mode":"normal","concurrency":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanCancelWhenIdleReturnsConflict(t *testing.T) {
	srv, _ := newTestServer(t)
	token, cookie := csrfTokenAndCookie(t, srv)

	req := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWrongHTTPMethodReturnsNotFound(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scan/start", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDiagnosticsEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["version"] == nil || body["db_path"] == nil || body["probe_mode"] == nil {
		t.Fatalf("missing expected keys: %+v", body)
	}
}

func TestAboutPageServesHTML(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("/api/diagnostics")) {
		t.Fatal("about page should reference diagnostics API")
	}
}

func TestRuntimeEndpointReturnsProbeMode(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/runtime", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode runtime response: %v", err)
	}
	if body["probe_mode"] == "" {
		t.Fatalf("expected probe_mode in runtime response")
	}
}

func TestSetupStatusNeedsAckOnFreshDB(t *testing.T) {
	srv, _ := newTestServerWithoutFirstRun(t)
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if needs, ok := out["needs_ack"].(bool); !ok || !needs {
		t.Fatalf("expected needs_ack true, got %+v", out)
	}
}

func TestScanStartForbiddenBeforeFirstRun(t *testing.T) {
	srv, _ := newTestServerWithoutFirstRun(t)
	token, cookie := csrfTokenAndCookie(t, srv)
	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","mode":"normal","concurrency":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSetupCompleteThenScanAccepted(t *testing.T) {
	srv, _ := newTestServerWithoutFirstRun(t)
	token, cookie := csrfTokenAndCookie(t, srv)

	complete := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","acknowledged":true}`))
	complete.Header.Set("Content-Type", "application/json")
	complete.Header.Set("X-CSRF-Token", token)
	complete.AddCookie(cookie)
	compRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(compRec, complete)
	if compRec.Code != http.StatusOK {
		t.Fatalf("setup complete expected 200, got %d body=%s", compRec.Code, compRec.Body.String())
	}

	start := httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"cidr":"10.0.0.0/30","mode":"normal","concurrency":1}`))
	start.Header.Set("Content-Type", "application/json")
	start.Header.Set("X-CSRF-Token", token)
	start.AddCookie(cookie)
	startRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(startRec, start)
	if startRec.Code != http.StatusAccepted {
		t.Fatalf("scan start expected 202, got %d body=%s", startRec.Code, startRec.Body.String())
	}
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
