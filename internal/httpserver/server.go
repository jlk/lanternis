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
	"sync"
	"time"

	"github.com/jlk/lanternis/internal/audit"
	"github.com/jlk/lanternis/internal/discovery"
	"github.com/jlk/lanternis/internal/discovery/passive"
	"github.com/jlk/lanternis/internal/store"
)

type Server struct {
	logger  *log.Logger
	store   *store.Store
	scanner *discovery.Scanner
	mux     *http.ServeMux
	dbPath  string
	version string
	debug   bool
}

// Config is optional metadata for diagnostics and the UI.
type Config struct {
	DBPath  string
	Version string
	Debug   bool
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
		debug:   cfg.Debug,
	}
	s.routes()
	if cfg.Debug {
		s.scanner.SetDebugLog(func(format string, args ...any) {
			s.debugf(format, args...)
		})
	}
	return s
}

func (s *Server) debugf(format string, args ...any) {
	if !s.debug {
		return
	}
	s.logger.Printf("[debug] "+format, args...)
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
    details.panel { padding: 10px 12px; }
    details.panel summary { cursor: pointer; font-weight: 600; margin: -4px 0 8px 0; }
    details.panel ul { margin: 0; padding-left: 1.25rem; color: var(--ln-muted); font-size: 14px; line-height: 1.5; }
    .table-toolbar { justify-content: space-between; align-items: center; margin-bottom: 8px; }
    caption { caption-side: top; text-align: left; font-size: 13px; color: var(--ln-muted); padding: 0 0 8px 0; }
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
        <label title="IPv4 network in CIDR form (e.g. 192.168.1.0/24). Only this range is scanned.">CIDR <input id="cidrInput" value="192.168.1.0/24" autocomplete="off" spellcheck="false" /></label>
        <label>Mode
          <select id="modeSelect" title="Controls how many hosts are probed in parallel (politeness vs speed).">
            <option value="light" title="12 parallel probes — gentlest on your LAN; slowest on large subnets.">light</option>
            <option value="normal" title="32 parallel probes — balanced default." selected>normal</option>
            <option value="thorough" title="48 parallel probes — fastest scan; more load on CPU and network.">thorough</option>
          </select>
        </label>
        <span id="statusText" class="status muted" aria-live="polite">Status: idle</span>
        <span id="probeBadge" class="muted" style="margin-left:8px;" aria-live="polite"></span>
      </div>
      <p id="modeHint" class="muted" style="margin: 10px 0 0 0; font-size: 14px; line-height: 1.45;"></p>
    </section>

    <details class="panel">
      <summary>Scan modes &amp; what “reachability” means</summary>
      <ul>
        <li><strong>light</strong> — Fewest parallel probes (12). Use on busy networks or when you want minimal impact.</li>
        <li><strong>normal</strong> — Default balance (32). Good starting point for most home /24 networks.</li>
        <li><strong>thorough</strong> — Most parallel probes (48). Finishes sooner; more CPU and traffic.</li>
        <li><strong>Reachability</strong> — What we could infer from the active probe (e.g. TCP connect or ICMP). <strong>Observed</strong> means we saw the host via passive discovery (ARP, mDNS, or SSDP) but the active probe did not get a reply. <strong>Unknown</strong> often means “no reply to our probe” and no passive hints yet — not “offline for sure.” Hidden rows may still be interesting later (M1a fingerprints, etc.).</li>
        <li><strong>Hints</strong> — Passive clues merged from this machine after you start a scan: ARP (Linux/macOS), local SSDP (UPnP discovery), and mDNS names heard on the LAN. They do not replace reachability from probes.</li>
      </ul>
    </details>

    <section class="panel">
      <div class="controls table-toolbar">
        <label class="setup-check" style="margin:0;"><input type="checkbox" id="hideUnknownReach" checked /> Hide unknown reachability</label>
        <span id="hostCount" class="muted" aria-live="polite"></span>
      </div>
      <table>
        <caption>Devices seen on your LAN for this database. Sort columns by clicking headers.</caption>
        <thead>
          <tr>
            <th data-col="ip" role="button" tabindex="0" title="Sort by IP">IP</th>
            <th data-col="reachability" role="button" tabindex="0" title="Sort by reachability">Reachability</th>
            <th data-col="label" role="button" tabindex="0" title="Sort by label">Label</th>
            <th data-col="confidence" role="button" tabindex="0" title="Sort by confidence">Confidence</th>
            <th data-col="last_seen" role="button" tabindex="0" title="Sort by last seen">Last seen</th>
            <th data-col="hints" role="button" tabindex="0" title="Sort by passive hints">Hints</th>
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
    const hideUnknownReach = document.getElementById("hideUnknownReach");
    const hostCount = document.getElementById("hostCount");
    const modeHint = document.getElementById("modeHint");
    const probeBadge = document.getElementById("probeBadge");

    let currentHosts = [];
    let sort = { col: "ip", dir: "asc" };
    let setupDone = false;

    const modeHints = {
      light: "Light: 12 parallel probes — gentlest on your LAN; slowest on large subnets.",
      normal: "Normal: 32 parallel probes — balanced default for most /24 home networks.",
      thorough: "Thorough: 48 parallel probes — faster finish; more CPU and network load."
    };

    function refreshModeHint() {
      modeHint.textContent = modeHints[modeSelect.value] || "";
    }

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
        probeBadge.textContent = "[Active probe: TCP]";
      } else if (mode === "icmp_echo") {
        probeBox.style.display = "block";
        probeBox.textContent = "Probe mode: ICMP echo. " + guidance;
        probeBadge.textContent = "[Active probe: ICMP]";
      } else {
        probeBox.style.display = "block";
        probeBox.textContent = "Probe mode: unknown.";
        probeBadge.textContent = "";
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
      if (s === "reachable") return 3;
      if (s === "observed") return 2;
      if (s === "unreachable") return 1;
      return 0; // unknown/other
    }

    function isUnknownReachability(h) {
      return String(h.reachability || "unknown").toLowerCase() === "unknown";
    }

    function hintSummary(h) {
      try {
        const rh = h.raw_hints;
        if (!rh || typeof rh !== "object") return "";
        const parts = [];
        const mdns = rh.mdns;
        if (mdns && Array.isArray(mdns.names) && mdns.names.length) {
          const extra = mdns.names.length > 1 ? " (+" + (mdns.names.length - 1) + ")" : "";
          parts.push("mDNS " + String(mdns.names[0]) + extra);
        }
        const ssdp = rh.ssdp;
        if (ssdp && Array.isArray(ssdp.st_types) && ssdp.st_types.length) {
          let st = String(ssdp.st_types[0]);
          if (st.length > 48) st = st.slice(0, 45) + "…";
          parts.push("SSDP " + st);
        }
        const arp = rh.arp;
        if (arp && arp.mac) parts.push("ARP " + String(arp.mac));
        return parts.join(" · ");
      } catch (e) {}
      return "";
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
        if (sort.col === "hints") return dir * hintSummary(a).localeCompare(hintSummary(b));
        const av = String((a[sort.col] ?? "")).toLowerCase();
        const bv = String((b[sort.col] ?? "")).toLowerCase();
        return dir * av.localeCompare(bv);
      });
      return rows;
    }

    function visibleHostRows() {
      const rows = sortedHosts();
      if (!hideUnknownReach.checked) {
        return rows;
      }
      return rows.filter((h) => !isUnknownReachability(h));
    }

    function renderHosts() {
      const total = (currentHosts || []).length;
      const rows = visibleHostRows();
      const hiddenUnknown = hideUnknownReach.checked
        ? (currentHosts || []).filter(isUnknownReachability).length
        : 0;
      hostsBody.innerHTML = "";
      if (!total) {
        hostCount.textContent = "";
        hostsBody.innerHTML = "<tr><td colspan='6' class='muted'>Nothing here yet. Run a first scan.</td></tr>";
        return;
      }
      if (!rows.length) {
        if (hideUnknownReach.checked && hiddenUnknown > 0) {
          hostsBody.innerHTML = "<tr><td colspan='6' class='muted'>Every row is hidden: all addresses have unknown reachability with the current probe. Uncheck &quot;Hide unknown reachability&quot; to see them.</td></tr>";
        } else {
          hostsBody.innerHTML = "<tr><td colspan='6' class='muted'>No rows to show.</td></tr>";
        }
        hostCount.textContent = "Showing 0 of " + total + (hiddenUnknown ? " (" + hiddenUnknown + " hidden)" : "");
        return;
      }
      hostCount.textContent = "Showing " + rows.length + " of " + total + (hiddenUnknown ? " (" + hiddenUnknown + " unknown hidden)" : "");
      for (const h of rows) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + (h.ip || "") + "</td>" +
          "<td>" + (h.reachability || "unknown") + "</td>" +
          "<td>" + (h.label || "Unknown") + "</td>" +
          "<td>" + (h.confidence || "unknown") + "</td>" +
          "<td>" + (h.last_seen ? new Date(h.last_seen).toLocaleString() : "") + "</td>" +
          "<td class='muted'>" + hintSummary(h) + "</td>";
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
    hideUnknownReach.addEventListener("change", () => renderHosts());
    modeSelect.addEventListener("change", refreshModeHint);

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
        refreshModeHint();
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
	scanRunID, err := s.scanner.Start(context.Background(), req.CIDR, req.Concurrency, func(result discovery.Result) error {
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

	scanStartedAt := time.Now()
	s.debugf("scan active probe start scanner_run_id=%d cidr=%s mode=%s concurrency=%d probe_mode=%s",
		scanRunID, req.CIDR, req.Mode, req.Concurrency, discovery.ProbeMode())
	passiveDone := make(chan passiveOutcome, 1)
	go s.runPassiveDiscovery(req.CIDR, passiveDone)

	dbRunID, err := s.store.InsertScanRun(r.Context(), req.Mode)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.debugf("scan db_run scan_id=%d scanner_run_id=%d cidr=%s", dbRunID, scanRunID, req.CIDR)
	s.logger.Printf("scan started scan_id=%d cidr=%s mode=%s concurrency=%d", dbRunID, req.CIDR, req.Mode, req.Concurrency)
	_ = audit.Append(r.Context(), s.store, "scan_started", map[string]any{
		"scan_id": dbRunID,
		"cidr":    req.CIDR,
		"mode":    req.Mode,
	})

	go s.watchAndFinalize(dbRunID, scanStartedAt, req.CIDR, passiveDone)
	writeJSON(w, http.StatusAccepted, map[string]any{
		// scan_id is the SQLite scan_runs primary key; the scanner's internal runID is not stable across runs.
		"scan_id": dbRunID,
		"status":  s.scanner.Status(),
	})
}

// passiveOutcome is merge counts from one passive discovery pass (ARP / SSDP / mDNS).
type passiveOutcome struct {
	ARP   int
	SSDP  int
	MDNS  int
}

func (s *Server) runPassiveDiscovery(cidr string, done chan<- passiveOutcome) {
	bg := context.Background()
	s.debugf("passive discovery start cidr=%s", cidr)
	if s.debug {
		b, err := passive.LANBindingForCIDR(cidr)
		if err != nil {
			s.debugf("passive LAN binding: %v", err)
		} else if b.LocalIP != "" {
			s.debugf("passive LAN binding: interface=%s local_ip=%s (SSDP + mDNS multicast)", b.InterfaceName, b.LocalIP)
		} else {
			s.debugf("passive LAN binding: no local IPv4 in %s — using OS default (SSDP/mDNS may see nothing)", cidr)
		}
	}
	arpN, _, err := s.runPassiveStep("ARP", cidr, func() (int, passive.ApplyDetail, error) {
		return passive.ApplyARPHints(bg, s.store, cidr)
	}, true)
	if err != nil {
		arpN = 0
	}
	var ssdpN, mdnsN int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _, err := s.runPassiveStep("SSDP", cidr, func() (int, passive.ApplyDetail, error) {
			return passive.ApplySSDPHints(bg, s.store, cidr, 0)
		}, false)
		if err == nil {
			ssdpN = n
		}
	}()
	go func() {
		defer wg.Done()
		n, _, err := s.runPassiveStep("mDNS", cidr, func() (int, passive.ApplyDetail, error) {
			return passive.ApplyMDNSHints(bg, s.store, cidr, 0)
		}, false)
		if err == nil {
			mdnsN = n
		}
	}()
	wg.Wait()
	o := passiveOutcome{ARP: arpN, SSDP: ssdpN, MDNS: mdnsN}
	select {
	case done <- o:
	default:
	}
}

func (s *Server) runPassiveStep(name, cidr string, fn func() (int, passive.ApplyDetail, error), useEntryWording bool) (int, passive.ApplyDetail, error) {
	t0 := time.Now()
	merged, detail, err := fn()
	elapsed := time.Since(t0).Round(time.Millisecond)
	if s.debug {
		s.debugf("passive %s: elapsed=%s collected=%d in_cidr=%d merged=%d err=%v",
			name, elapsed, detail.Collected, detail.InCIDR, merged, err)
	}
	if err != nil {
		s.logger.Printf("passive %s hints: %v", name, err)
		return merged, detail, err
	}
	if merged > 0 {
		if useEntryWording {
			s.logger.Printf("passive %s hints: merged %d entries for %s", name, merged, cidr)
		} else {
			s.logger.Printf("passive %s hints: merged %d hosts for %s", name, merged, cidr)
		}
	}
	return merged, detail, nil
}

func countReachabilityInCIDR(hosts []store.Host, cidr string) (reachable, unreachable, unknown, observed int) {
	for _, h := range hosts {
		if !passive.IPInCIDR(h.IP, cidr) {
			continue
		}
		switch strings.ToLower(h.Reachability) {
		case "reachable":
			reachable++
		case "unreachable":
			unreachable++
		case "observed":
			observed++
		default:
			unknown++
		}
	}
	return
}

func (s *Server) watchAndFinalize(dbRunID int64, scanStartedAt time.Time, cidr string, passiveDone <-chan passiveOutcome) {
	if s.debug {
		s.debugf("watch scan_id=%d waiting for active probe to finish", dbRunID)
	}
	var lastProgressLog time.Time
	for {
		st := s.scanner.Status()
		if s.debug && st.Running {
			if lastProgressLog.IsZero() || time.Since(lastProgressLog) >= 2*time.Second {
				lastProgressLog = time.Now()
				s.debugf("scan scan_id=%d progress=%d/%d phase=%s", dbRunID, st.Completed, st.Total, st.ScanPhase)
			}
		}
		if !st.Running {
			if s.debug {
				s.debugf("scan scan_id=%d wall=%s phase=%s completed=%d total=%d",
					dbRunID, time.Since(scanStartedAt).Round(time.Millisecond), st.ScanPhase, st.Completed, st.Total)
			}
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

			var po passiveOutcome
			select {
			case po = <-passiveDone:
			case <-time.After(90 * time.Second):
			}
			ctx := context.Background()
			hosts, err := s.store.ListHosts(ctx)
			if err != nil {
				s.logger.Printf("scan summary scan_id=%d: list hosts: %v", dbRunID, err)
				return
			}
			reach, unreach, unk, obs := countReachabilityInCIDR(hosts, cidr)
			s.logger.Printf("scan summary scan_id=%d cidr=%s active_probed=%d reachable=%d unreachable=%d unknown=%d observed=%d passive_arp_merged=%d passive_ssdp_merged=%d passive_mdns_merged=%d",
				dbRunID, cidr, st.Total, reach, unreach, unk, obs, po.ARP, po.SSDP, po.MDNS)
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
