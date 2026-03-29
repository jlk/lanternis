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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &captureStatusWriter{ResponseWriter: w}
		s.mux.ServeHTTP(lw, r)
		status := lw.status
		if status == 0 {
			status = http.StatusOK
		}
		s.logger.Printf("[access] %s %s %d %s %s",
			r.Method, r.URL.RequestURI(), status, r.RemoteAddr, time.Since(start).Truncate(time.Microsecond))
	})
}

// captureStatusWriter records the HTTP status code for access logs.
type captureStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *captureStatusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureStatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/about", s.handleAbout)
	s.mux.HandleFunc("/api/csrf", s.handleCSRF)
	s.mux.HandleFunc("/api/diagnostics", s.handleDiagnostics)
	s.mux.HandleFunc("/api/hosts", s.handleHosts)
	s.mux.HandleFunc("/api/host", s.handleHostDetail)
	s.mux.HandleFunc("/api/runtime", s.handleRuntime)
	s.mux.HandleFunc("/api/setup/status", s.handleSetupStatus)
	s.mux.HandleFunc("/api/setup/complete", s.requireCSRF(s.handleSetupComplete))
	s.mux.HandleFunc("/api/scan/status", s.handleScanStatus)
	s.mux.HandleFunc("/api/scan/start", s.requireCSRF(s.handleScanStart))
	s.mux.HandleFunc("/api/scan/cancel", s.requireCSRF(s.handleScanCancel))
	s.mux.HandleFunc("/api/support/export", s.requireCSRF(s.handleSupportExport))
	s.mux.HandleFunc("/api/scan/diff", s.handleScanDiff)
	s.mux.HandleFunc("/api/scan/diff/export", s.requireCSRF(s.handleScanDiffExport))
	s.mux.HandleFunc("/api/scan/runs", s.handleScanRuns)
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
    :root {
      --ln-bg:#f8f9fa; --ln-surface:#fff; --ln-text:#1a1a1a; --ln-muted:#6c757d; --ln-border:#dee2e6;
      --ln-accent:#0d6efd; --ln-warn-bg:#fff3cd; --ln-warn-border:#ffe69c; --ln-on-accent:#fff;
    }
    html[data-theme="dark"] {
      --ln-bg:#121416; --ln-surface:#1a1d21; --ln-text:#e8eaed; --ln-muted:#9aa0a6; --ln-border:#3c4043;
      --ln-accent:#5c9eff; --ln-warn-bg:#3d3200; --ln-warn-border:#6b5a00; --ln-on-accent:#0d1117;
    }
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: var(--ln-bg); color: var(--ln-text); transition: background 0.15s ease, color 0.15s ease; }
    main { max-width: 1080px; margin: 0 auto; padding: 12px 16px 16px 16px; min-height: 100vh; display: flex; flex-direction: column; }
    h1 { margin: 0; font-size: 20px; line-height: 1.1; letter-spacing: -0.01em; }
    .panel { background: var(--ln-surface); border: 1px solid var(--ln-border); border-radius: 4px; padding: 12px; margin-bottom: 10px; }
    .controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    label { font-size: 14px; color: var(--ln-muted); }
    input, select, button { font: inherit; min-height: 44px; padding: 9px 12px; border-radius: 4px; border: 1px solid var(--ln-border); background: var(--ln-surface); color: var(--ln-text); }
    input[type="checkbox"] { min-height: 0; width: 16px; height: 16px; padding: 0; }
    button.primary { background: var(--ln-accent); color: var(--ln-on-accent); border-color: var(--ln-accent); }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    table { width: 100%; border-collapse: collapse; background: var(--ln-surface); }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--ln-border); font-size: 14px; }
    th { font-weight: 600; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .topbar .right { display: flex; align-items: center; gap: 8px; }
    .subhead { margin: 0; font-size: 13px; line-height: 1.35; color: var(--ln-muted); }
    .results-panel { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    .results-panel .table-toolbar { margin-bottom: 10px; }
    .table-scroll { flex: 1; min-height: 0; overflow: auto; border: 1px solid var(--ln-border); border-radius: 4px; }
    .table-scroll table { border: 0; }
    .table-scroll thead th { position: sticky; top: 0; background: var(--ln-surface); z-index: 1; }
    .table-scroll tbody tr.host-row:hover { background: color-mix(in srgb, var(--ln-accent) 8%, transparent); }
    .table-scroll th, .table-scroll td { border-bottom: 1px solid var(--ln-border); }
    .table-scroll tr:last-child td { border-bottom: 0; }
    .scanbar { display: grid; grid-template-columns: auto auto 1fr 1fr auto auto auto; gap: 8px; align-items: center; }
    .scanbar .status { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .scanbar label { display: inline-flex; align-items: center; gap: 8px; }
    .scanbar label input { width: 180px; }
    @media (max-width: 880px) {
      .scanbar { grid-template-columns: 1fr 1fr; }
      .scanbar label input { width: 100%; }
    }
    td.num { font-variant-numeric: tabular-nums; }
    .muted { color: var(--ln-muted); }
    .status { display: inline-block; min-width: 280px; }
    #errorBox { display: none; background: var(--ln-warn-bg); border: 1px solid var(--ln-warn-border); padding: 8px 10px; border-radius: 4px; margin-bottom: 12px; }
    #diffStrip { display: none; font-size: 14px; padding: 6px 10px; margin-bottom: 8px; background: var(--ln-surface); border: 1px dashed var(--ln-border); border-radius: 4px; }
    #portBanner { display: none; background: var(--ln-warn-bg); border: 1px solid var(--ln-warn-border); padding: 6px 10px; border-radius: 4px; margin-bottom: 8px; }
    #portBanner .banner-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; justify-content: space-between; }
    #portBanner .banner-actions { display: flex; flex-wrap: wrap; gap: 8px; flex-shrink: 0; }
    #scanRunsPanel table { font-size: 13px; }
    #scanRunsPanel td.num { white-space: nowrap; }
    #scanRunsPanel .drawer-section { margin-top: 12px; }
    #scanRunsPanel summary + .drawer-section { margin-top: 0; }
    #scanRunsPanel .drawer-subhead { margin: 0 0 8px 0; font-size: 13px; font-weight: 600; color: var(--ln-text); }
    #scanRunsPanel .drawer-lead { margin: 0 0 8px 0; font-size: 13px; line-height: 1.35; }
    .first-run-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: none; align-items: center; justify-content: center; z-index: 1000; padding: 16px; }
    .first-run-overlay.open { display: flex; }
    .first-run-card { max-width: 520px; width: 100%; }
    .first-run-card p { line-height: 1.45; margin: 0 0 10px 0; }
    .setup-check { display: flex; gap: 10px; align-items: flex-start; margin: 12px 0; font-size: 14px; }
    .setup-check input { margin-top: 3px; }
    details.panel { padding: 10px 12px; }
    details.panel summary { cursor: pointer; font-weight: 600; margin: -4px 0 8px 0; }
    details.panel ul { margin: 0; padding-left: 1.25rem; color: var(--ln-muted); font-size: 14px; line-height: 1.5; }
    .table-toolbar { display: flex; flex-wrap: wrap; gap: 12px; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .column-picker { font-size: 13px; color: var(--ln-muted); }
    .column-picker summary { cursor: pointer; font-weight: 600; color: var(--ln-text); list-style: none; display: inline-flex; align-items: center; gap: 8px; padding: 9px 12px; border: 1px solid var(--ln-border); border-radius: 4px; background: var(--ln-surface); min-height: 44px; }
    .column-picker[open] summary { border-color: color-mix(in srgb, var(--ln-accent) 50%, var(--ln-border)); box-shadow: 0 0 0 2px color-mix(in srgb, var(--ln-accent) 22%, transparent); }
    .column-picker summary::-webkit-details-marker { display: none; }
    .column-picker .column-check-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 6px 12px; margin-top: 8px; padding: 10px; border: 1px solid var(--ln-border); border-radius: 4px; background: var(--ln-surface); max-width: 520px; }
    caption { caption-side: top; text-align: left; font-size: 13px; color: var(--ln-muted); padding: 0 0 8px 0; }
    #hostsTable tbody tr.host-row { cursor: pointer; }
    #hostsTable tbody tr.host-row:hover { background: color-mix(in srgb, var(--ln-accent) 8%, transparent); }
    .host-detail-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.45); display: none; align-items: center; justify-content: center; z-index: 1001; padding: 16px; }
    .host-detail-overlay.open { display: flex; }
    .host-detail-card { max-width: 720px; width: 100%; max-height: 88vh; overflow: auto; position: relative; }
    .host-detail-card .hdr { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 12px; }
    .host-detail-section { margin-bottom: 16px; }
    .host-detail-section h3 { margin: 0 0 8px 0; font-size: 15px; font-weight: 600; }
    .open-ports-list .port-chip { display: inline-block; padding: 3px 9px; margin: 0 6px 6px 0; font-size: 13px; border-radius: 4px; border: 1px solid var(--ln-border); background: color-mix(in srgb, var(--ln-accent) 6%, transparent); }
    .web-ui-links a { font-weight: 500; }
    .fp-dl { display: grid; grid-template-columns: 9rem 1fr; gap: 4px 12px; font-size: 14px; margin: 0; }
    .fp-dl dt { color: var(--ln-muted); margin: 0; }
    .fp-dl dd { margin: 0; }
    .hints-pre { font-size: 12px; line-height: 1.4; overflow: auto; max-height: 220px; padding: 10px; background: var(--ln-bg); border: 1px solid var(--ln-border); border-radius: 4px; white-space: pre-wrap; word-break: break-word; }
    .host-detail-table { width: 100%; font-size: 13px; border-collapse: collapse; }
    .host-detail-table th, .host-detail-table td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--ln-border); }
  </style>
</head>
<body>
  <main>
    <div class="topbar">
      <div>
        <h1>Lanternis</h1>
        <p class="subhead">Local network inventory. Unknown means unknown — we do not invent confidence.</p>
      </div>
      <div class="right">
        <button type="button" id="themeToggle" aria-pressed="false" title="Switch to dark mode">Dark mode</button>
        <a class="muted" href="/about">Diagnostics</a>
      </div>
    </div>
    <div id="errorBox" role="status" aria-live="polite"></div>

    <div id="firstRunOverlay" class="first-run-overlay" role="dialog" aria-modal="true" aria-labelledby="firstRunTitle">
      <div class="first-run-card panel">
        <h2 id="firstRunTitle">Before your first scan</h2>
        <p class="muted">Lanternis runs only on this computer. Inventory and audit events are stored in a local SQLite database file (see the <code>-db</code> flag). Nothing is sent to the cloud by default.</p>
        <p class="muted">The app is designed to cap audit growth over time (for example, pruning events older than about 90 days or beyond roughly 100k rows—exact limits may evolve in a future release). Your scan inventory remains on disk until you delete the database.</p>
        <p class="muted">Only scan networks you own or are explicitly authorized to test. Unauthorized scanning may violate law or policy.</p>
        <label>Network range (CIDR) <input id="setupCidrInput" type="text" autocomplete="off" /></label>
        <label>NVD API key <span class="muted">(optional)</span> <input id="setupNvdInput" type="password" autocomplete="off" placeholder="For future CVE lookups" title="Stored only in your local DB; not sent until you use a feature that calls NVD." /></label>
        <p class="muted" style="font-size:13px;margin-top:-4px;">If you add a key, it stays on this machine. Lanternis does not upload it by default.</p>
        <label class="setup-check"><input type="checkbox" id="setupAck" /> I confirm I only scan networks I own or am authorized to test.</label>
        <div class="controls" style="margin-top: 8px;">
          <button type="button" id="setupContinueBtn" class="primary">Continue</button>
        </div>
      </div>
    </div>

    <div id="hostDetailOverlay" class="host-detail-overlay" role="dialog" aria-modal="true" aria-labelledby="hostDetailTitle">
      <div class="host-detail-card panel">
        <div class="hdr">
          <h2 id="hostDetailTitle" style="margin:0;font-size:1.15rem;">Device</h2>
          <button type="button" id="hostDetailClose" class="muted" title="Close">Close</button>
        </div>
        <div id="hostDetailContent"></div>
      </div>
    </div>

    <section class="panel">
      <div class="scanbar">
        <button id="startBtn" class="primary">Start scan</button>
        <button id="cancelBtn">Cancel</button>
        <label title="IPv4 network in CIDR form (e.g. 192.168.1.0/24). Only this range is scanned.">CIDR <input id="cidrInput" value="192.168.1.0/24" autocomplete="off" spellcheck="false" /></label>
        <label>Mode
          <select id="modeSelect" title="Parallel host workers and TCP port breadth (politeness vs coverage). ICMP build ignores port lists.">
            <option value="light" title="12 parallel host probes; smallest TCP port set (web-focused).">light</option>
            <option value="normal" title="32 parallel; balanced TCP port list (web + common IoT)." selected>normal</option>
            <option value="thorough" title="48 parallel; widest TCP port list; more traffic per host.">thorough</option>
            <option value="deep" title="Same breadth as thorough; longer per-host probes; optional raw TCP stack fingerprint on Linux (elevated privileges).">deep</option>
          </select>
        </label>
        <span id="statusText" class="status muted" aria-live="polite">Status: idle</span>
        <span id="probeBadge" class="muted" aria-live="polite"></span>
        <button type="button" id="diffExportBtn" title="Download scan diff JSON">Export diff</button>
      </div>
      <p id="modeHint" class="muted" style="margin: 8px 0 0 0; font-size: 13px; line-height: 1.35;"></p>
    </section>

    <section class="panel results-panel">
      <div id="diffStrip" role="status" aria-live="polite"></div>
      <div id="portBanner" role="region" aria-label="New open ports since last scan">
        <div class="banner-row">
          <span id="portBannerText"></span>
          <span class="banner-actions">
            <button type="button" id="portBannerSnooze">Snooze 24h</button>
            <button type="button" id="portBannerDismiss">Dismiss until next scan</button>
          </span>
        </div>
      </div>
      <div class="controls table-toolbar">
        <label class="setup-check" style="margin:0;"><input type="checkbox" id="hideUnknownReach" checked /> Hide unknown reachability</label>
        <details class="column-picker">
          <summary>Table columns</summary>
          <div class="column-check-grid" id="hostColumnPicker" aria-label="Choose visible columns"></div>
        </details>
        <span id="hostCount" class="muted" aria-live="polite"></span>
      </div>
      <div class="table-scroll" id="hostsTableScroll" role="region" aria-label="Devices table">
        <table id="hostsTable">
          <thead>
            <tr>
              <th data-col="ip" role="button" tabindex="0" title="Sort by IP">IP</th>
              <th data-col="reachability" role="button" tabindex="0" title="Sort by reachability">Reachability</th>
              <th data-col="open_ports" role="button" tabindex="0" title="Sort by open ports (active probe)">Open ports</th>
              <th data-col="vendor" role="button" tabindex="0" title="Sort by vendor (fingerprint)">Vendor</th>
              <th data-col="device_class" role="button" tabindex="0" title="Sort by inferred device kind">Kind</th>
              <th data-col="os" role="button" tabindex="0" title="Sort by inferred OS (fingerprint)">OS</th>
              <th data-col="label" role="button" tabindex="0" title="Sort by label">Label</th>
              <th data-col="confidence" role="button" tabindex="0" title="Sort by confidence">Confidence</th>
              <th data-col="last_seen" role="button" tabindex="0" title="Sort by last seen">Last seen</th>
              <th data-col="hints" role="button" tabindex="0" title="Sort by passive hints">Hints</th>
            </tr>
          </thead>
          <tbody id="hostsBody"></tbody>
        </table>
      </div>
    </section>

    <details class="panel" id="scanRunsPanel">
      <summary>Recent scans &amp; mode help</summary>
      <div class="drawer-section">
        <p class="muted drawer-lead">Completed and in-progress runs for this database (newest first).</p>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Started</th>
              <th>Ended</th>
              <th>Mode</th>
              <th>CIDR</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="scanRunsBody"></tbody>
        </table>
      </div>
      <div class="drawer-section">
        <h3 class="drawer-subhead">Scan modes &amp; what “reachability” means</h3>
        <ul>
          <li><strong>light</strong> — Fewest parallel <em>host</em> workers (12) and the <strong>smallest TCP port set</strong> (HTTP/S-focused). Gentlest on busy LANs.</li>
          <li><strong>normal</strong> — Default balance (32 workers; web + common IoT ports like RTSP/UPnP-alt).</li>
          <li><strong>thorough</strong> — Most workers (48) and the <strong>widest TCP port set</strong> (adds SSH, SMB, MQTT, Home Assistant, etc.). Finishes sooner per host batch; more traffic.</li>
          <li><strong>deep</strong> — Same port list as thorough with <strong>longer connect budgets</strong>. Use when you explicitly want heavier probes; on Linux, raw SYN/SYN+ACK TCP fingerprinting (needs capability/root) runs in this mode only.</li>
          <li><strong>Open ports</strong> — All probe-list ports that accepted a TCP connect in the current mode (not a full port map). ICMP builds show <code>icmp</code> when echo reply was seen. Empty when the probe got no reply.</li>
          <li><strong>Reachability</strong> — What we could infer from the active probe (e.g. TCP connect or ICMP). <strong>Observed</strong> means we saw the host via passive discovery (ARP, mDNS, or SSDP) but the active probe did not get a reply. <strong>Unknown</strong> often means “no reply to our probe” and no passive hints yet — not “offline for sure.” Hidden rows may still be interesting later (M1a fingerprints, etc.).</li>
          <li><strong>Hints</strong> — Passive clues merged from this machine after you start a scan: ARP (Linux/macOS), local SSDP (UPnP discovery), and mDNS names heard on the LAN. They do not replace reachability from probes.</li>
        </ul>
      </div>
    </details>
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
    const firstRunOverlay = document.getElementById("firstRunOverlay");
    const setupCidrInput = document.getElementById("setupCidrInput");
    const setupAck = document.getElementById("setupAck");
    const setupContinueBtn = document.getElementById("setupContinueBtn");
    const setupNvdInput = document.getElementById("setupNvdInput");
    const hideUnknownReach = document.getElementById("hideUnknownReach");
    const hostCount = document.getElementById("hostCount");
    const modeHint = document.getElementById("modeHint");
    const probeBadge = document.getElementById("probeBadge");
    const diffStrip = document.getElementById("diffStrip");
    const portBanner = document.getElementById("portBanner");
    const portBannerText = document.getElementById("portBannerText");
    const portBannerDismiss = document.getElementById("portBannerDismiss");
    const themeToggle = document.getElementById("themeToggle");
    const diffExportBtn = document.getElementById("diffExportBtn");
    const STORAGE_THEME = "ln_theme";
    const STORAGE_PORT_DISMISS = "ln_port_banner_dismiss_scan_id";
    const STORAGE_PORT_SNOOZE = "ln_port_banner_snooze_until";
    const STORAGE_HOST_TABLE_COLS = "ln_host_table_columns_v1";
    const HOST_TABLE_COLS = [
      { id: "ip", label: "IP", locked: true },
      { id: "reachability", label: "Reachability" },
      { id: "open_ports", label: "Open ports" },
      { id: "vendor", label: "Vendor" },
      { id: "device_class", label: "Kind" },
      { id: "os", label: "OS" },
      { id: "label", label: "Label" },
      { id: "confidence", label: "Confidence" },
      { id: "last_seen", label: "Last seen" },
      { id: "hints", label: "Hints" },
    ];
    const scanRunsBody = document.getElementById("scanRunsBody");
    const portBannerSnooze = document.getElementById("portBannerSnooze");
    const hostDetailOverlay = document.getElementById("hostDetailOverlay");
    const hostDetailTitle = document.getElementById("hostDetailTitle");
    const hostDetailContent = document.getElementById("hostDetailContent");
    const hostDetailClose = document.getElementById("hostDetailClose");
    const hostColumnPicker = document.getElementById("hostColumnPicker");

    let currentHosts = [];
    let sort = { col: "ip", dir: "asc" };
    let setupDone = false;

    function defaultHostColVisibility() {
      const out = {};
      for (const c of HOST_TABLE_COLS) {
        if (c.locked) {
          continue;
        }
        out[c.id] = true;
      }
      return out;
    }

    function loadHostColVisibility() {
      try {
        const raw = localStorage.getItem(STORAGE_HOST_TABLE_COLS);
        if (!raw) {
          return defaultHostColVisibility();
        }
        const o = JSON.parse(raw);
        const d = defaultHostColVisibility();
        if (o && typeof o === "object") {
          for (const k of Object.keys(d)) {
            if (typeof o[k] === "boolean") {
              d[k] = o[k];
            }
          }
        }
        return d;
      } catch (e) {
        return defaultHostColVisibility();
      }
    }

    function saveHostColVisibility() {
      try {
        localStorage.setItem(STORAGE_HOST_TABLE_COLS, JSON.stringify(hostColVisibility));
      } catch (e) {}
    }

    let hostColVisibility = loadHostColVisibility();

    function hostColVisible(id) {
      if (id === "ip") {
        return true;
      }
      return hostColVisibility[id] !== false;
    }

    function visibleHostTableColCount() {
      let n = 0;
      for (const c of HOST_TABLE_COLS) {
        if (hostColVisible(c.id)) {
          n++;
        }
      }
      return n;
    }

    function applyHostTableHeaderVisibility() {
      for (const th of tableHeaders) {
        const col = th.getAttribute("data-col");
        th.style.display = hostColVisible(col) ? "" : "none";
      }
    }

    function initHostColumnPicker() {
      if (!hostColumnPicker) {
        return;
      }
      hostColumnPicker.innerHTML = "";
      for (const c of HOST_TABLE_COLS) {
        if (c.locked) {
          continue;
        }
        const lab = document.createElement("label");
        lab.className = "setup-check";
        lab.style.margin = "0";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = hostColVisible(c.id);
        cb.addEventListener("change", () => {
          hostColVisibility[c.id] = cb.checked;
          saveHostColVisibility();
          applyHostTableHeaderVisibility();
          updateHeaderIndicators();
          renderHosts();
        });
        lab.appendChild(cb);
        lab.appendChild(document.createTextNode(" " + c.label));
        hostColumnPicker.appendChild(lab);
      }
    }

    const modeHints = {
      light: "Light: 12 parallel host probes + smallest TCP port set (web).",
      normal: "Normal: 32 parallel + balanced TCP ports (web + common IoT).",
      thorough: "Thorough: 48 parallel + widest TCP port list (more services probed per host).",
      deep: "Deep: same ports as thorough + longer probes; Linux raw TCP stack fingerprint (opt-in, elevated privileges)."
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
      if (mode === "thorough" || mode === "deep") return 48;
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
        probeBadge.textContent = "[Active probe: TCP]";
      } else if (mode === "icmp_echo") {
        probeBadge.textContent = "[Active probe: ICMP]";
      } else {
        probeBadge.textContent = "";
      }
      if (guidance) {
        probeBadge.title = guidance;
      } else {
        probeBadge.removeAttribute("title");
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
        body: JSON.stringify({
          cidr: cidr,
          acknowledged: true,
          nvd_api_key: (setupNvdInput && setupNvdInput.value) ? setupNvdInput.value.trim() : ""
        })
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

    function osTableCell(h) {
      const fp = h.fingerprint;
      if (!fp || typeof fp !== "object") {
        return "<td class='muted'>—</td>";
      }
      if (fp.os_conflict) {
        const full = String(fp.os_detail || "Conflicting OS hints").trim();
        return "<td class='muted' title=\"" + esc(full) + "\">Conflict</td>";
      }
      const det = String(fp.os_detail || "").trim();
      const fam = String(fp.os_family || "").trim();
      let text = det || (fam && fam !== "unknown" ? fam : "");
      if (!text) {
        return "<td class='muted'>—</td>";
      }
      const full = text;
      if (text.length > 56) {
        text = text.slice(0, 53) + "…";
      }
      return "<td class='muted' title=\"" + esc(full) + "\">" + esc(text) + "</td>";
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

    function openPortsSortKey(h) {
      if (!h.open_ports || !h.open_ports.length) return "";
      return h.open_ports.slice().sort().join(",");
    }

    function osSortKey(h) {
      const fp = h.fingerprint;
      if (!fp || typeof fp !== "object") {
        return "";
      }
      if (fp.os_conflict) {
        return "conflict";
      }
      const det = String(fp.os_detail || "").toLowerCase().trim();
      const fam = String(fp.os_family || "").toLowerCase().trim();
      return (det || fam || "").trim();
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
        if (sort.col === "open_ports") return dir * openPortsSortKey(a).localeCompare(openPortsSortKey(b));
        if (sort.col === "hints") return dir * hintSummary(a).localeCompare(hintSummary(b));
        if (sort.col === "vendor") {
          return dir * String(a.vendor || "").toLowerCase().localeCompare(String(b.vendor || "").toLowerCase());
        }
        if (sort.col === "device_class") {
          return dir * String(a.device_class || "").toLowerCase().localeCompare(String(b.device_class || "").toLowerCase());
        }
        if (sort.col === "os") {
          return dir * osSortKey(a).localeCompare(osSortKey(b));
        }
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
      const colSpan = String(visibleHostTableColCount());
      if (!total) {
        hostCount.textContent = "";
        hostsBody.innerHTML = "<tr><td colspan=\"" + colSpan + "\" class='muted'>Nothing here yet. Run a first scan.</td></tr>";
        return;
      }
      if (!rows.length) {
        if (hideUnknownReach.checked && hiddenUnknown > 0) {
          hostsBody.innerHTML = "<tr><td colspan=\"" + colSpan + "\" class='muted'>Every row is hidden: all addresses have unknown reachability with the current probe. Uncheck &quot;Hide unknown reachability&quot; to see them.</td></tr>";
        } else {
          hostsBody.innerHTML = "<tr><td colspan=\"" + colSpan + "\" class='muted'>No rows to show.</td></tr>";
        }
        hostCount.textContent = "Showing 0 of " + total + (hiddenUnknown ? " (" + hiddenUnknown + " hidden)" : "");
        return;
      }
      hostCount.textContent = "Showing " + rows.length + " of " + total + (hiddenUnknown ? " (" + hiddenUnknown + " unknown hidden)" : "");
      for (const h of rows) {
        const tr = document.createElement("tr");
        tr.className = "host-row";
        tr.setAttribute("data-ip", h.ip || "");
        tr.setAttribute("tabindex", "0");
        tr.setAttribute("role", "button");
        tr.setAttribute("title", "Show device details");
        const vend = String(h.vendor || "").trim();
        const kind = String(h.device_class || "").trim();
        const cells = [];
        if (hostColVisible("ip")) {
          cells.push("<td class='num'>" + (h.ip || "") + "</td>");
        }
        if (hostColVisible("reachability")) {
          cells.push("<td>" + (h.reachability || "unknown") + "</td>");
        }
        if (hostColVisible("open_ports")) {
          cells.push("<td class='muted num'>" + (Array.isArray(h.open_ports) && h.open_ports.length ? h.open_ports.join(", ") : "—") + "</td>");
        }
        if (hostColVisible("vendor")) {
          cells.push("<td class='muted'>" + (vend ? esc(vend) : "—") + "</td>");
        }
        if (hostColVisible("device_class")) {
          cells.push("<td class='muted'>" + (kind ? esc(kind) : "—") + "</td>");
        }
        if (hostColVisible("os")) {
          cells.push(osTableCell(h));
        }
        if (hostColVisible("label")) {
          cells.push("<td>" + (h.label || "Unknown") + "</td>");
        }
        if (hostColVisible("confidence")) {
          cells.push("<td>" + (h.confidence || "unknown") + "</td>");
        }
        if (hostColVisible("last_seen")) {
          cells.push("<td>" + (h.last_seen ? new Date(h.last_seen).toLocaleString() : "") + "</td>");
        }
        if (hostColVisible("hints")) {
          cells.push("<td class='muted'>" + hintSummary(h) + "</td>");
        }
        tr.innerHTML = cells.join("");
        hostsBody.appendChild(tr);
      }
    }

    function esc(s) {
      return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    /** Host part for URL authority (bracket IPv6 literals). */
    function ipHostForURL(ip) {
      if (!ip || typeof ip !== "string") {
        return "";
      }
      if (ip.indexOf(":") !== -1) {
        return "[" + ip + "]";
      }
      return ip;
    }

    function fmtDetailTime(iso) {
      try {
        return new Date(iso).toLocaleString();
      } catch (e) {
        return String(iso);
      }
    }

    function sortDetailPorts(a, b) {
      if (a === "icmp" && b !== "icmp") {
        return 1;
      }
      if (b === "icmp" && a !== "icmp") {
        return -1;
      }
      const na = parseInt(a, 10);
      const nb = parseInt(b, 10);
      if (!isNaN(na) && !isNaN(nb) && String(na) === a && String(nb) === b) {
        return na - nb;
      }
      return String(a).localeCompare(String(b));
    }

    function vendorSubtitle(fp) {
      if (!fp || typeof fp !== "object") {
        return "";
      }
      if (fp.manufacturer) {
        return "from device description (UPnP)";
      }
      const sigs = fp.signals || [];
      for (let i = 0; i < sigs.length; i++) {
        if (sigs[i].source === "oui") {
          return "from IEEE OUI (MAC prefix)";
        }
      }
      return "";
    }

    function renderHostDetail(d) {
      const h = d.host;
      const hist = d.scan_history || [];
      const findings = d.findings || [];
      const fp = h.fingerprint || null;
      const vendorDisp = String(h.vendor || "").trim();
      let fpHtml = "<p class='muted'>No fingerprint record yet. After a scan completes, we store merged evidence: passive ARP / SSDP / mDNS, reverse DNS (PTR), UPnP device XML when available, OUI, HTTP(S) title and Server headers, TLS cert names, SSH banners, and (when ports are open) anonymous SMB strings and an RDP negotiation peek. <strong>Deep</strong> scan mode on Linux may add a raw SYN/SYN+ACK TCP fingerprint if the process has permission — not SNMP.</p>";
      if (fp && typeof fp === "object") {
        const sigs = fp.signals || [];
        const sigLis = sigs.map(function (s) {
          return "<li><strong>" + esc(s.source) + "</strong>" +
            (s.field ? " · <span class='muted'>" + esc(s.field) + "</span>" : "") +
            " — <code>" + esc(s.value || "") + "</code></li>";
        }).join("");
        fpHtml = "<dl class='fp-dl'>";
        if (fp.ladder_max != null && fp.ladder_max !== undefined) {
          fpHtml += "<dt>Identity ladder</dt><dd>L" + esc(String(fp.ladder_max)) + " (see docs)</dd>";
        }
        const kindDisp = String(h.device_class || fp.device_class || "").trim();
        if (kindDisp) {
          fpHtml += "<dt>Inferred kind</dt><dd>" + esc(kindDisp) + " <span class='muted'>(fused ports, SSDP types, PTR, HTTP banners)</span></dd>";
        }
        if (fp.summary) {
          fpHtml += "<dt>Summary</dt><dd>" + esc(fp.summary) + "</dd>";
        }
        if (fp.manufacturer) {
          fpHtml += "<dt>Manufacturer</dt><dd>" + esc(fp.manufacturer) + "</dd>";
        }
        if (fp.model) {
          fpHtml += "<dt>Model</dt><dd>" + esc(fp.model) + "</dd>";
        }
        if (fp.firmware_version) {
          fpHtml += "<dt>Firmware</dt><dd>" + esc(fp.firmware_version) + "</dd>";
        }
        if (fp.os_family || fp.os_detail) {
          var osDisp = (fp.os_detail && String(fp.os_detail).trim()) || String(fp.os_family || "");
          var osNote = "SSH / HTTP / SSDP / SMB / RDP peek; best-effort.";
          if (fp.os_conflict) {
            osNote = "Independent hints disagreed; family left unknown — see evidence chain.";
          } else {
            var hasStack = false;
            for (var si = 0; si < sigs.length; si++) {
              if (sigs[si].source === "os_tcp_stack") { hasStack = true; break; }
            }
            if (hasStack) {
              osNote += " Raw TCP stack fingerprint (deep scan on Linux) needs elevated privileges; heuristic.";
            }
          }
          fpHtml += "<dt>OS (inferred)</dt><dd>" + esc(osDisp) +
            " <span class='muted'>(" + osNote + ")</span></dd>";
        }
        if (fp.serial) {
          fpHtml += "<dt>Serial</dt><dd>" + esc(fp.serial) + "</dd>";
        }
        fpHtml += "</dl>";
        if (sigLis) {
          fpHtml += "<p class='muted' style='margin:10px 0 4px 0;'>Evidence chain</p><ul style='margin:0;padding-left:1.2rem;font-size:14px;line-height:1.45;'>" + sigLis + "</ul>";
        }
      }
      let histHtml = "<p class='muted'>No rows yet. History is filled from completed scans (last " + String(10) + " runs retained).</p>";
      if (hist.length) {
        histHtml = "<table class='host-detail-table'><thead><tr><th>Scan</th><th>Started</th><th>Ended</th><th>Mode</th><th>CIDR</th><th>Label</th><th>Reach.</th><th>Ports</th></tr></thead><tbody>";
        for (let i = 0; i < hist.length; i++) {
          const row = hist[i];
          const ports = (row.open_ports && row.open_ports.length) ? row.open_ports.join(", ") : "—";
          histHtml += "<tr><td class='num'>" + esc(String(row.scan_id)) + "</td>" +
            "<td class='num'>" + fmtDetailTime(row.started_at) + "</td>" +
            "<td class='num'>" + (row.ended_at ? fmtDetailTime(row.ended_at) : "—") + "</td>" +
            "<td>" + esc(row.mode || "") + "</td>" +
            "<td class='num'>" + esc(row.cidr || "") + "</td>" +
            "<td>" + esc(row.label || "") + "</td>" +
            "<td>" + esc(row.reachability || "") + "</td>" +
            "<td class='muted num'>" + esc(ports) + "</td></tr>";
        }
        histHtml += "</tbody></table>";
      }
      const hintsStr = JSON.stringify(h.raw_hints || {}, null, 2);
      const vsub = vendorSubtitle(fp);
      const vendorLine = vendorDisp
        ? "<strong>" + esc(vendorDisp) + "</strong>" + (vsub ? " <span class='muted'>(" + esc(vsub) + ")</span>" : "")
        : "<span class='muted'>—</span>";
      const kindRow = String(h.device_class || (fp && fp.device_class) || "").trim();
      const kindLine = kindRow
        ? "<strong>" + esc(kindRow) + "</strong> <span class='muted'>(heuristic)</span>"
        : "<span class='muted'>—</span>";
      const portList = (h.open_ports && h.open_ports.length)
        ? h.open_ports.slice().map(function (p) { return String(p); }).sort(sortDetailPorts)
        : [];
      const portsBlock = portList.length
        ? "<p class='open-ports-list' style='margin:0;line-height:1.6;'>" + portList.map(function (p) {
          return "<code class='port-chip'>" + esc(p) + "</code>";
        }).join(" ") + "</p>"
        : "<p class='muted' style='margin:0;'>No TCP ports from the last probe in this scan mode (or host did not respond to probes).</p>";
      const urlHost = ipHostForURL(h.ip || "");
      const portSet = {};
      for (let i = 0; i < portList.length; i++) {
        portSet[String(portList[i]).trim()] = true;
      }
      const webParts = [];
      if (urlHost) {
        if (portSet["80"]) {
          webParts.push("<a class=\"web-ui-link\" href=\"" + esc("http://" + urlHost + "/") + "\" target=\"_blank\" rel=\"noopener noreferrer\">HTTP <span class='muted'>(80)</span></a>");
        }
        if (portSet["443"]) {
          webParts.push("<a class=\"web-ui-link\" href=\"" + esc("https://" + urlHost + "/") + "\" target=\"_blank\" rel=\"noopener noreferrer\">HTTPS <span class='muted'>(443)</span></a>");
        }
      }
      const webLinksBlock = webParts.length
        ? "<p class='web-ui-links' style='margin:10px 0 0 0;font-size:14px;'>Web UI: " + webParts.join(" · ") + " <span class='muted' style='font-size:12px;'>(opens in a new tab; certificate warnings are normal on LAN)</span></p>"
        : "";
      let findingsHtml = "<p class='muted' style='margin:0;'>No structured version findings yet. After a scan, vendor/product/version hints tied to a surface (UPnP, SSH, …) appear here. CVE lookup uses only rows marked vuln-ready.</p>";
      if (findings.length) {
        findingsHtml = "<table class='host-detail-table'><thead><tr><th>Surface</th><th>Product</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>";
        for (let fi = 0; fi < findings.length; fi++) {
          const f = findings[fi];
          const prod = [f.vendor_guess, f.product_guess].filter(function (x) { return x && String(x).trim(); }).join(" · ") || "—";
          const ev = (f.evidence_kind || "") + (f.evidence_digest ? " · " + String(f.evidence_digest).slice(0, 12) + "…" : "");
          findingsHtml += "<tr><td class='muted'>" + esc(f.surface || "") + "</td>" +
            "<td>" + esc(prod) + "</td>" +
            "<td class='num'>" + esc(f.version_guess || "—") + "</td>" +
            "<td>" + esc(f.version_confidence || "") + (f.vuln_ready ? " <span class='muted'>(vuln-ready)</span>" : "") + "</td>" +
            "<td class='muted' style='font-size:13px;max-width:14rem;word-break:break-all;'>" + esc(ev || "—") + "</td></tr>";
        }
        findingsHtml += "</tbody></table>";
      }
      hostDetailContent.innerHTML =
        "<section class='host-detail-section'><h3>Address</h3><p style='margin:0;'><code>" + esc(h.ip || "") + "</code></p></section>" +
        "<section class='host-detail-section'><h3>Open ports</h3>" +
        "<p class='muted' style='margin:0 0 10px 0;font-size:13px;'>Ports that accepted a TCP connect (or <code>icmp</code> when echo was seen) in the current probe mode — not a full port map.</p>" +
        portsBlock +
        webLinksBlock +
        "</section>" +
        "<section class='host-detail-section'><h3>Current row</h3><p style='margin:0 0 8px 0;'>Kind " + kindLine + "</p>" +
        "<p style='margin:0 0 8px 0;'>Vendor " + vendorLine + "</p>" +
        "<p style='margin:0;'>Reachability <strong>" + esc(h.reachability || "unknown") + "</strong> · Confidence <strong>" + esc(h.confidence || "unknown") + "</strong> · Last seen " +
        (h.last_seen ? fmtDetailTime(h.last_seen) : "—") + "</p></section>" +
        "<section class='host-detail-section'><h3>Findings</h3><p class='muted' style='margin:0 0 10px 0;font-size:13px;'>Per-surface software identity for vulnerability-oriented review (not the same as display label).</p>" +
        findingsHtml + "</section>" +
        "<section class='host-detail-section'><h3>Fingerprint reasoning</h3>" + fpHtml + "</section>" +
        "<section class='host-detail-section'><h3>Passive / discovery hints</h3><pre class='hints-pre'></pre></section>" +
        "<section class='host-detail-section'><h3>Scan history (snapshots)</h3>" + histHtml + "</section>";
      const pre = hostDetailContent.querySelector(".hints-pre");
      if (pre) {
        pre.textContent = hintsStr;
      }
    }

    function closeHostDetail() {
      hostDetailOverlay.classList.remove("open");
    }

    async function openHostDetail(ip) {
      if (!ip) {
        return;
      }
      clearError();
      hostDetailTitle.textContent = "Device · " + ip;
      hostDetailContent.innerHTML = "<p class='muted'>Loading…</p>";
      hostDetailOverlay.classList.add("open");
      try {
        const d = await fetchJSON("/api/host?ip=" + encodeURIComponent(ip));
        renderHostDetail(d);
      } catch (e) {
        hostDetailContent.innerHTML = "<p class='muted'>" + esc(e.message) + "</p>";
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
        if (!th.dataset.sortTitle) {
          th.dataset.sortTitle = th.textContent.replace(/ [▲▼]$/, "").trim();
        }
        const base = th.dataset.sortTitle || "";
        const active = col === sort.col;
        th.setAttribute("aria-sort", active ? (sort.dir === "asc" ? "ascending" : "descending") : "none");
        th.textContent = base + (active ? (sort.dir === "asc" ? " ▲" : " ▼") : "");
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

    function syncThemeToggleLabel() {
      const dark = document.documentElement.getAttribute("data-theme") === "dark";
      themeToggle.textContent = dark ? "Light mode" : "Dark mode";
      themeToggle.title = dark ? "Switch to light mode" : "Switch to dark mode";
      themeToggle.setAttribute("aria-pressed", dark ? "true" : "false");
    }

    function initTheme() {
      const saved = localStorage.getItem(STORAGE_THEME);
      if (saved === "dark") {
        document.documentElement.setAttribute("data-theme", "dark");
      } else if (saved === "light") {
        document.documentElement.removeAttribute("data-theme");
      } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        document.documentElement.setAttribute("data-theme", "dark");
      }
      syncThemeToggleLabel();
    }

    function renderDiffStrip(d) {
      if (!d || !d.previous_scan_id) {
        diffStrip.style.display = "none";
        diffStrip.textContent = "";
        return;
      }
      const a = (d.hosts_added || []).length;
      const r = (d.hosts_removed || []).length;
      const c = (d.hosts_changed || []).length;
      if (a + r + c === 0) {
        diffStrip.style.display = "none";
        diffStrip.textContent = "";
        return;
      }
      diffStrip.style.display = "block";
      const rLabel = r === 1 ? "1 host" : r + " hosts";
      diffStrip.textContent = "Since last scan: +" + a + " hosts · −" + rLabel + (c ? " · " + c + " changed" : "");
    }

    function renderPortBanner(d) {
      if (!d || !d.new_open_ports || !d.new_open_ports.length) {
        portBanner.style.display = "none";
        return;
      }
      const snoozeUntil = localStorage.getItem(STORAGE_PORT_SNOOZE);
      if (snoozeUntil) {
        const t = parseInt(snoozeUntil, 10);
        if (!Number.isNaN(t)) {
          if (Date.now() < t) {
            portBanner.style.display = "none";
            return;
          }
          localStorage.removeItem(STORAGE_PORT_SNOOZE);
        }
      }
      const sid = d.current_scan_id || 0;
      if (localStorage.getItem(STORAGE_PORT_DISMISS) === String(sid)) {
        portBanner.style.display = "none";
        return;
      }
      const n = d.new_open_ports.length;
      portBanner.style.display = "block";
      portBannerText.textContent = "New open ports on " + n + " host" + (n === 1 ? "" : "s") + " since last scan (" + (d.cidr || "scan range") + ").";
    }

    async function loadDiff() {
      try {
        const d = await fetchJSON("/api/scan/diff");
        renderDiffStrip(d);
        renderPortBanner(d);
      } catch (e) {
        diffStrip.style.display = "none";
        portBanner.style.display = "none";
      }
    }

    function renderScanRuns(data) {
      if (!scanRunsBody) return;
      const runs = (data && data.runs) || [];
      scanRunsBody.innerHTML = "";
      if (!runs.length) {
        scanRunsBody.innerHTML = "<tr><td colspan='6' class='muted'>No scans yet.</td></tr>";
        return;
      }
      for (const r of runs) {
        const tr = document.createElement("tr");
        const ended = r.ended_at ? new Date(r.ended_at).toLocaleString() : "—";
        const st = r.cancel_requested ? "Cancelled" : (r.ended_at ? "Done" : "Running");
        tr.innerHTML =
          "<td class='num'>" + (r.id || "") + "</td>" +
          "<td class='num'>" + (r.started_at ? new Date(r.started_at).toLocaleString() : "") + "</td>" +
          "<td class='num'>" + ended + "</td>" +
          "<td>" + (r.mode || "") + "</td>" +
          "<td class='num'>" + (r.cidr || "") + "</td>" +
          "<td>" + st + "</td>";
        scanRunsBody.appendChild(tr);
      }
    }

    async function loadScanRuns() {
      try {
        const data = await fetchJSON("/api/scan/runs");
        renderScanRuns(data);
      } catch (e) {
        if (scanRunsBody) {
          scanRunsBody.innerHTML = "<tr><td colspan='6' class='muted'>Could not load scan history.</td></tr>";
        }
      }
    }

    async function tick() {
      try {
        await loadStatus();
        await loadHosts();
        await loadDiff();
        await loadScanRuns();
      } catch (e) {
        showError(e.message);
      }
    }

    themeToggle.addEventListener("click", () => {
      const dark = document.documentElement.getAttribute("data-theme") === "dark";
      if (dark) {
        document.documentElement.removeAttribute("data-theme");
        localStorage.setItem(STORAGE_THEME, "light");
      } else {
        document.documentElement.setAttribute("data-theme", "dark");
        localStorage.setItem(STORAGE_THEME, "dark");
      }
      syncThemeToggleLabel();
    });
    portBannerSnooze.addEventListener("click", () => {
      const until = Date.now() + 24 * 60 * 60 * 1000;
      localStorage.setItem(STORAGE_PORT_SNOOZE, String(until));
      portBanner.style.display = "none";
    });
    portBannerDismiss.addEventListener("click", () => {
      fetchJSON("/api/scan/diff").then((d) => {
        if (d && d.current_scan_id) {
          localStorage.setItem(STORAGE_PORT_DISMISS, String(d.current_scan_id));
        }
        portBanner.style.display = "none";
      }).catch(() => { portBanner.style.display = "none"; });
    });
    diffExportBtn.addEventListener("click", () => {
      fetch("/api/scan/diff/export", { method: "POST", headers: { "X-CSRF-Token": csrfToken } })
        .then((res) => {
          if (!res.ok) throw new Error("export failed: " + res.status);
          return res.blob();
        })
        .then((blob) => {
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "lanternis-scan-diff.json";
          a.click();
          URL.revokeObjectURL(url);
        })
        .catch((e) => showError(e.message));
    });
    startBtn.addEventListener("click", () => startScan().catch((e) => showError(e.message)));
    cancelBtn.addEventListener("click", () => cancelScan().catch((e) => showError(e.message)));
    setupContinueBtn.addEventListener("click", () => completeFirstRun().catch((e) => showError(e.message)));
    hideUnknownReach.addEventListener("change", () => renderHosts());
    modeSelect.addEventListener("change", refreshModeHint);

    hostsBody.addEventListener("click", (e) => {
      const tr = e.target.closest("tr.host-row");
      if (!tr || !hostsBody.contains(tr)) {
        return;
      }
      const ip = tr.getAttribute("data-ip");
      if (ip) {
        openHostDetail(ip).catch((err) => showError(err.message));
      }
    });
    hostsBody.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") {
        return;
      }
      const tr = e.target.closest("tr.host-row");
      if (!tr || !hostsBody.contains(tr)) {
        return;
      }
      e.preventDefault();
      const ip = tr.getAttribute("data-ip");
      if (ip) {
        openHostDetail(ip).catch((err) => showError(err.message));
      }
    });
    hostDetailClose.addEventListener("click", () => closeHostDetail());
    hostDetailOverlay.addEventListener("click", (e) => {
      if (e.target === hostDetailOverlay) {
        closeHostDetail();
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && hostDetailOverlay.classList.contains("open")) {
        closeHostDetail();
      }
    });

    for (const th of tableHeaders) {
      th.addEventListener("click", () => setSort(th.getAttribute("data-col")));
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setSort(th.getAttribute("data-col"));
        }
      });
    }

    (async function boot() {
      try {
        initTheme();
        await initCSRF();
        await loadSetupStatus();
        refreshModeHint();
        await loadRuntime();
        initHostColumnPicker();
        applyHostTableHeaderVisibility();
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
	out := make([]hostJSON, len(hosts))
	for i := range hosts {
		out[i] = newHostJSON(hosts[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
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
	nvdOK, err := s.store.NVDAPIKeyConfigured(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_ack":              !done,
		"suggested_cidr":         suggested,
		"nvd_api_key_configured": nvdOK,
	})
}

type setupCompleteReq struct {
	CIDR         string `json:"cidr"`
	Acknowledged bool   `json:"acknowledged"`
	NVDAPIKey    string `json:"nvd_api_key"`
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
	if err := s.store.CompleteFirstRun(r.Context(), req.CIDR, req.NVDAPIKey); err != nil {
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

	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid CIDR"))
		return
	}

	if s.scanner.Status().Running {
		writeErr(w, http.StatusConflict, errors.New("scan already running"))
		return
	}

	dbRunID, err := s.store.InsertScanRun(r.Context(), req.Mode, req.CIDR)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	scanStartedAt := time.Now()
	passiveDone := make(chan passiveOutcome, 1)
	go s.runPassiveDiscovery(req.CIDR, passiveDone)

	// Important: do not bind the scan lifetime to the HTTP request context.
	// Request contexts are cancelled when the handler returns, which would immediately cancel the scan.
	scanRunID, err := s.scanner.Start(context.Background(), req.CIDR, discovery.ScanOptions{
		Concurrency: req.Concurrency,
		TCPProfile:  req.Mode,
	}, func(result discovery.Result) error {
		return s.store.UpsertHost(context.Background(), store.Host{
			IP:           result.IP,
			Reachability: result.Reachability,
			OpenPorts:    result.OpenPorts,
			Label:        "",
			Confidence:   result.Confidence,
			LastSeen:     result.ObservedAt,
		})
	})
	if err != nil {
		_ = s.store.MarkScanEnded(context.Background(), dbRunID, true)
		if err.Error() == "scan already running" {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	s.debugf("scan active probe start scanner_run_id=%d cidr=%s mode=%s concurrency=%d probe_mode=%s",
		scanRunID, req.CIDR, req.Mode, req.Concurrency, discovery.ProbeMode())
	s.debugf("scan db_run scan_id=%d scanner_run_id=%d cidr=%s", dbRunID, scanRunID, req.CIDR)
	s.logger.Printf("scan started scan_id=%d cidr=%s mode=%s concurrency=%d", dbRunID, req.CIDR, req.Mode, req.Concurrency)
	_ = audit.Append(r.Context(), s.store, "scan_started", map[string]any{
		"scan_id": dbRunID,
		"cidr":    req.CIDR,
		"mode":    req.Mode,
	})

	go s.watchAndFinalize(dbRunID, scanStartedAt, req.CIDR, req.Mode, passiveDone)
	writeJSON(w, http.StatusAccepted, map[string]any{
		// scan_id is the SQLite scan_runs primary key; the scanner's internal runID is not stable across runs.
		"scan_id": dbRunID,
		"status":  s.scanner.Status(),
	})
}

// passiveOutcome is merge counts from one passive discovery pass (ARP / SSDP / mDNS).
type passiveOutcome struct {
	ARP  int
	SSDP int
	MDNS int
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

func (s *Server) watchAndFinalize(dbRunID int64, scanStartedAt time.Time, cidr string, tcpScanMode string, passiveDone <-chan passiveOutcome) {
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
			if !cancelled {
				s.applyFingerprints(ctx, cidr, hosts, tcpScanMode)
				hosts, err = s.store.ListHosts(ctx)
				if err != nil {
					s.logger.Printf("scan summary scan_id=%d: list hosts after fingerprint: %v", dbRunID, err)
					return
				}
				if err := s.store.ReplaceScanSnapshot(ctx, dbRunID, cidr, hosts); err != nil {
					s.logger.Printf("scan snapshot scan_id=%d: %v", dbRunID, err)
				}
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
