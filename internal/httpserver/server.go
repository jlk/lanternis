package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
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
	dbPath  string
	version string
}

// Config is optional metadata for diagnostics and the UI.
type Config struct {
	DBPath  string
	Version string
}

func New(logger *log.Logger, st *store.Store, scanner *discovery.Scanner, cfg Config) *Server {
	v := cfg.Version
	if v == "" {
		v = "dev"
	}
	s := &Server{
		logger:  logger,
		store:   st,
		scanner: scanner,
		mux:     http.NewServeMux(),
		dbPath:  cfg.DBPath,
		version: v,
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/about", s.handleAbout)
	s.mux.HandleFunc("/api/csrf", s.handleCSRF)
	s.mux.HandleFunc("/api/diagnostics", s.handleDiagnostics)
	s.mux.HandleFunc("/api/hosts", s.handleHosts)
	s.mux.HandleFunc("/api/runtime", s.handleRuntime)
	s.mux.HandleFunc("/api/setup/status", s.handleSetupStatus)
	s.mux.HandleFunc("/api/setup/complete", s.requireCSRF(s.handleSetupComplete))
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
    #probeBox { display: none; background: var(--ln-warn-bg); border: 1px solid #ffe69c; padding: 8px 10px; border-radius: 4px; margin-bottom: 12px; }
    .first-run-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: none; align-items: center; justify-content: center; z-index: 1000; padding: 16px; }
    .first-run-overlay.open { display: flex; }
    .first-run-card { max-width: 520px; width: 100%; }
    .first-run-card p { line-height: 1.45; margin: 0 0 10px 0; }
    .setup-check { display: flex; gap: 10px; align-items: flex-start; margin: 12px 0; font-size: 14px; }
    .setup-check input { margin-top: 3px; }
  </style>
</head>
<body>
  <main>
    <h1>Lanternis</h1>
    <p class="muted">Local network scanner (M1). Unknown means unknown; we do not invent confidence.</p>
    <div id="errorBox" role="status" aria-live="polite"></div>
    <div id="probeBox" class="muted" role="status" aria-live="polite"></div>

    <div id="firstRunOverlay" class="first-run-overlay" role="dialog" aria-modal="true" aria-labelledby="firstRunTitle">
      <div class="first-run-card panel">
        <h2 id="firstRunTitle">Before your first scan</h2>
        <p class="muted">Lanternis runs only on this computer. Inventory and audit events are stored in a local SQLite database file (see the <code>-db</code> flag). Nothing is sent to the cloud by default.</p>
        <p class="muted">Only scan networks you own or are explicitly authorized to test. Unauthorized scanning may violate law or policy.</p>
        <label>Network range (CIDR) <input id="setupCidrInput" type="text" autocomplete="off" /></label>
        <label class="setup-check"><input type="checkbox" id="setupAck" /> I confirm I only scan networks I own or am authorized to test.</label>
        <div class="controls" style="margin-top: 8px;">
          <button type="button" id="setupContinueBtn" class="primary">Continue</button>
        </div>
      </div>
    </div>

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
          <tr>
            <th data-col="ip" role="button" tabindex="0" title="Sort by IP">IP</th>
            <th data-col="reachability" role="button" tabindex="0" title="Sort by reachability">Reachability</th>
            <th data-col="label" role="button" tabindex="0" title="Sort by label">Label</th>
            <th data-col="confidence" role="button" tabindex="0" title="Sort by confidence">Confidence</th>
            <th data-col="last_seen" role="button" tabindex="0" title="Sort by last seen">Last seen</th>
          </tr>
        </thead>
        <tbody id="hostsBody"></tbody>
      </table>
    </section>

    <p class="muted">Only scans your configured network from this computer. <a href="/about">Diagnostics</a></p>
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
    const tableHeaders = Array.from(document.querySelectorAll("thead th[data-col]"));
    const probeBox = document.getElementById("probeBox");
    const firstRunOverlay = document.getElementById("firstRunOverlay");
    const setupCidrInput = document.getElementById("setupCidrInput");
    const setupAck = document.getElementById("setupAck");
    const setupContinueBtn = document.getElementById("setupContinueBtn");

    let currentHosts = [];
    let sort = { col: "ip", dir: "asc" };
    let setupDone = false;

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

    async function loadRuntime() {
      const data = await fetchJSON("/api/runtime");
      const mode = data.probe_mode || "unknown";
      const guidance = data.probe_guidance || "";
      if (mode === "tcp_fallback") {
        probeBox.style.display = "block";
        probeBox.textContent = "Probe mode: TCP fallback. " + guidance;
      } else if (mode === "icmp_echo") {
        probeBox.style.display = "block";
        probeBox.textContent = "Probe mode: ICMP echo. " + guidance;
      } else {
        probeBox.style.display = "block";
        probeBox.textContent = "Probe mode: unknown.";
      }
    }

    async function loadSetupStatus() {
      const data = await fetchJSON("/api/setup/status");
      setupDone = !data.needs_ack;
      const suggested = data.suggested_cidr || "192.168.1.0/24";
      setupCidrInput.value = suggested;
      cidrInput.value = suggested;
      if (data.needs_ack) {
        firstRunOverlay.classList.add("open");
        setupAck.checked = false;
        startBtn.disabled = true;
        cancelBtn.disabled = true;
      } else {
        firstRunOverlay.classList.remove("open");
      }
    }

    async function completeFirstRun() {
      clearError();
      if (!setupAck.checked) {
        showError("Please confirm you are authorized to scan this network.");
        return;
      }
      const cidr = setupCidrInput.value.trim();
      await fetchJSON("/api/setup/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ cidr: cidr, acknowledged: true })
      });
      firstRunOverlay.classList.remove("open");
      setupDone = true;
      cidrInput.value = cidr;
      startBtn.disabled = false;
      cancelBtn.disabled = true;
    }

    async function loadHosts() {
      const data = await fetchJSON("/api/hosts");
      currentHosts = data.hosts || [];
      renderHosts();
    }

    function ipv4Key(ip) {
      // Returns [a,b,c,d] for IPv4; otherwise null.
      if (!ip) return null;
      const parts = String(ip).trim().split(".");
      if (parts.length !== 4) return null;
      const out = [];
      for (const p of parts) {
        if (p === "" || p.length > 3) return null;
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
        out.push(n);
      }
      return out;
    }

    function compareIP(a, b) {
      const ak = ipv4Key(a);
      const bk = ipv4Key(b);
      if (ak && bk) {
        for (let i = 0; i < 4; i++) {
          if (ak[i] !== bk[i]) return ak[i] - bk[i];
        }
        return 0;
      }
      // Fallback: string compare.
      return String(a || "").localeCompare(String(b || ""));
    }

    function rankConfidence(v) {
      const s = String(v || "unknown").toLowerCase();
      if (s === "high") return 3;
      if (s === "medium") return 2;
      if (s === "low") return 1;
      return 0; // unknown/other
    }

    function rankReachability(v) {
      const s = String(v || "unknown").toLowerCase();
      if (s === "reachable") return 2;
      if (s === "unreachable") return 1;
      return 0; // unknown/other
    }

    function sortedHosts() {
      const rows = (currentHosts || []).slice();
      rows.sort((a, b) => {
        const dir = sort.dir === "desc" ? -1 : 1;
        if (sort.col === "ip") return dir * compareIP(a.ip, b.ip);
        if (sort.col === "last_seen") {
          const at = a.last_seen ? new Date(a.last_seen).getTime() : 0;
          const bt = b.last_seen ? new Date(b.last_seen).getTime() : 0;
          return dir * (at - bt);
        }
        if (sort.col === "confidence") return dir * (rankConfidence(a.confidence) - rankConfidence(b.confidence));
        if (sort.col === "reachability") return dir * (rankReachability(a.reachability) - rankReachability(b.reachability));
        const av = String((a[sort.col] ?? "")).toLowerCase();
        const bv = String((b[sort.col] ?? "")).toLowerCase();
        return dir * av.localeCompare(bv);
      });
      return rows;
    }

    function renderHosts() {
      const rows = sortedHosts();
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

    function setSort(col) {
      if (sort.col === col) {
        sort.dir = (sort.dir === "asc") ? "desc" : "asc";
      } else {
        sort.col = col;
        sort.dir = "asc";
      }
      updateHeaderIndicators();
      renderHosts();
    }

    function updateHeaderIndicators() {
      for (const th of tableHeaders) {
        const col = th.getAttribute("data-col");
        const active = col === sort.col;
        th.setAttribute("aria-sort", active ? (sort.dir === "asc" ? "ascending" : "descending") : "none");
        th.textContent = th.textContent.replace(/ [▲▼]$/, "");
        if (active) {
          th.textContent = th.textContent + (sort.dir === "asc" ? " ▲" : " ▼");
        }
      }
    }

    async function loadStatus() {
      const st = await fetchJSON("/api/scan/status");
      statusText.textContent = "Status: " + (st.scan_phase || "idle") + " | " + (st.completed || 0) + "/" + (st.total || 0);
      if (!setupDone) {
        startBtn.disabled = true;
        cancelBtn.disabled = true;
        return;
      }
      startBtn.disabled = !!st.running;
      cancelBtn.disabled = !st.running;
    }

    async function startScan() {
      clearError();
      if (!setupDone) {
        showError("Complete the first-run setup before scanning.");
        return;
      }
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
    setupContinueBtn.addEventListener("click", () => completeFirstRun().catch((e) => showError(e.message)));

    for (const th of tableHeaders) {
      th.addEventListener("click", () => setSort(th.getAttribute("data-col")));
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setSort(th.getAttribute("data-col"));
        }
      });
    }

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
        await loadSetupStatus();
        await loadRuntime();
        updateHeaderIndicators();
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

func (s *Server) handleRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"probe_mode":     discovery.ProbeMode(),
		"probe_guidance": discovery.ProbeGuidance(),
	})
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	done, err := s.store.FirstRunComplete(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	suggested, err := s.store.SuggestedCIDR(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_ack":      !done,
		"suggested_cidr": suggested,
	})
}

type setupCompleteReq struct {
	CIDR         string `json:"cidr"`
	Acknowledged bool   `json:"acknowledged"`
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req setupCompleteReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if !req.Acknowledged {
		writeErr(w, http.StatusBadRequest, errors.New("acknowledgment required"))
		return
	}
	if req.CIDR == "" {
		req.CIDR = "192.168.1.0/24"
	}
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid CIDR"))
		return
	}
	if err := s.store.CompleteFirstRun(r.Context(), req.CIDR); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = audit.Append(r.Context(), s.store, "first_run_completed", map[string]any{
		"cidr": req.CIDR,
	})
	s.logger.Printf("first-run setup completed cidr=%s", req.CIDR)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cidr": req.CIDR})
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

	done, err := s.store.FirstRunComplete(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !done {
		writeErr(w, http.StatusForbidden, errors.New("complete first-run setup before scanning"))
		return
	}

	// Important: do not bind the scan lifetime to the HTTP request context.
	// Request contexts are cancelled when the handler returns, which would immediately cancel the scan.
	_, err = s.scanner.Start(context.Background(), req.CIDR, req.Concurrency, func(result discovery.Result) error {
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
	s.logger.Printf("scan started scan_id=%d cidr=%s mode=%s concurrency=%d", dbRunID, req.CIDR, req.Mode, req.Concurrency)
	_ = audit.Append(r.Context(), s.store, "scan_started", map[string]any{
		"scan_id": dbRunID,
		"cidr":    req.CIDR,
		"mode":    req.Mode,
	})

	go s.watchAndFinalize(dbRunID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		// scan_id is the SQLite scan_runs primary key; the scanner's internal runID is not stable across runs.
		"scan_id": dbRunID,
		"status":  s.scanner.Status(),
	})
}

func (s *Server) watchAndFinalize(dbRunID int64) {
	for {
		st := s.scanner.Status()
		if !st.Running {
			cancelled := st.ScanPhase == "cancelled"
			s.logger.Printf("scan finished scan_id=%d phase=%s completed=%d total=%d cancelled=%t", dbRunID, st.ScanPhase, st.Completed, st.Total, cancelled)
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
	s.logger.Printf("scan cancel requested")
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
