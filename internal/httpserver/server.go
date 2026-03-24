package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
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
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lanternis</title>
  <style>
    :root { --ln-bg:#f8f9fa; --ln-surface:#fff; --ln-text:#1a1a1a; --ln-muted:#6c757d; --ln-border:#dee2e6; --ln-accent:#0d6efd; --ln-warn-bg:#fff3cd; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: var(--ln-bg); color: var(--ln-text); }
    main { max-width: 1080px; margin: 0 auto; padding: 16px; }
    h1 { margin-top: 0; }
    .panel { background: var(--ln-surface); border: 1px solid var(--ln-border); border-radius: 4px; padding: 12px; margin-bottom: 12px; }
    .controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    label { font-size: 14px; color: var(--ln-muted); }
    input, select, button { font: inherit; padding: 8px 10px; border-radius: 4px; border: 1px solid var(--ln-border); background: #fff; }
    button.primary { background: var(--ln-accent); color: #fff; border-color: var(--ln-accent); }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    table { width: 100%; border-collapse: collapse; background: var(--ln-surface); }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--ln-border); font-size: 14px; }
    th { font-weight: 600; }
    .muted { color: var(--ln-muted); }
    .status { display: inline-block; min-width: 280px; }
    #errorBox { display: none; background: var(--ln-warn-bg); border: 1px solid #ffe69c; padding: 8px 10px; border-radius: 4px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <main>
    <h1>Lanternis</h1>
    <p class="muted">Local network scanner (M1). Unknown means unknown; we do not invent confidence.</p>
    <div id="errorBox" role="status" aria-live="polite"></div>

    <section class="panel">
      <div class="controls">
        <button id="startBtn" class="primary">Start scan</button>
        <button id="cancelBtn">Cancel</button>
        <label>CIDR <input id="cidrInput" value="192.168.1.0/24" /></label>
        <label>Mode
          <select id="modeSelect">
            <option value="light">light</option>
            <option value="normal" selected>normal</option>
            <option value="thorough">thorough</option>
          </select>
        </label>
        <span id="statusText" class="status muted" aria-live="polite">Status: idle</span>
      </div>
    </section>

    <section class="panel">
      <table>
        <thead>
          <tr><th>IP</th><th>Reachability</th><th>Label</th><th>Confidence</th><th>Last seen</th></tr>
        </thead>
        <tbody id="hostsBody"></tbody>
      </table>
    </section>

    <p class="muted">Only scans your configured network from this computer.</p>
  </main>
  <script>
    let csrfToken = "";
    const startBtn = document.getElementById("startBtn");
    const cancelBtn = document.getElementById("cancelBtn");
    const statusText = document.getElementById("statusText");
    const hostsBody = document.getElementById("hostsBody");
    const errorBox = document.getElementById("errorBox");
    const cidrInput = document.getElementById("cidrInput");
    const modeSelect = document.getElementById("modeSelect");

    function showError(msg) {
      errorBox.style.display = "block";
      errorBox.textContent = msg;
    }

    function clearError() {
      errorBox.style.display = "none";
      errorBox.textContent = "";
    }

    async function fetchJSON(path, options = {}) {
      const res = await fetch(path, options);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || ("request failed: " + res.status));
      }
      return body;
    }

    function mapModeToConcurrency(mode) {
      if (mode === "light") return 12;
      if (mode === "thorough") return 48;
      return 32;
    }

    async function initCSRF() {
      const data = await fetchJSON("/api/csrf");
      csrfToken = data.csrf_token || "";
    }

    async function loadHosts() {
      const data = await fetchJSON("/api/hosts");
      const rows = data.hosts || [];
      hostsBody.innerHTML = "";
      if (!rows.length) {
        hostsBody.innerHTML = "<tr><td colspan='5' class='muted'>Nothing here yet. Run a first scan.</td></tr>";
        return;
      }
      for (const h of rows) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + (h.ip || "") + "</td>" +
          "<td>" + (h.reachability || "unknown") + "</td>" +
          "<td>" + (h.label || "Unknown") + "</td>" +
          "<td>" + (h.confidence || "unknown") + "</td>" +
          "<td>" + (h.last_seen ? new Date(h.last_seen).toLocaleString() : "") + "</td>";
        hostsBody.appendChild(tr);
      }
    }

    async function loadStatus() {
      const st = await fetchJSON("/api/scan/status");
      statusText.textContent = "Status: " + (st.scan_phase || "idle") + " | " + (st.completed || 0) + "/" + (st.total || 0);
      startBtn.disabled = !!st.running;
      cancelBtn.disabled = !st.running;
    }

    async function startScan() {
      clearError();
      await fetchJSON("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({
          cidr: cidrInput.value,
          mode: modeSelect.value,
          concurrency: mapModeToConcurrency(modeSelect.value)
        })
      });
      await loadStatus();
    }

    async function cancelScan() {
      clearError();
      await fetchJSON("/api/scan/cancel", {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken }
      });
      await loadStatus();
    }

    startBtn.addEventListener("click", () => startScan().catch((e) => showError(e.message)));
    cancelBtn.addEventListener("click", () => cancelScan().catch((e) => showError(e.message)));

    async function tick() {
      try {
        await loadStatus();
        await loadHosts();
      } catch (e) {
        showError(e.message);
      }
    }

    (async function boot() {
      try {
        await initCSRF();
        await tick();
        setInterval(tick, 1500);
      } catch (e) {
        showError(e.message);
      }
    })();
  </script>
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
		if origin != "" && !isLoopbackOrigin(origin) {
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

func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "[::1]")
}
