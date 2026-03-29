package httpserver

import (
	"context"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/jlk/lanternis/internal/discovery"
)

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	payload, err := s.buildDiagnostics(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) buildDiagnostics(ctx context.Context) (map[string]any, error) {
	modPath, modVer := "", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		modPath = bi.Main.Path
		modVer = bi.Main.Version
	}
	last, err := s.store.LastScanRun(ctx)
	if err != nil {
		return nil, err
	}
	events, err := s.store.ListRecentAuditEvents(ctx, 25)
	if err != nil {
		return nil, err
	}
	var lastScan any
	if last != nil {
		m := map[string]any{
			"id":               last.ID,
			"started_at":       last.StartedAt.UTC().Format(time.RFC3339Nano),
			"mode":             last.Mode,
			"cidr":             last.CIDR,
			"cancel_requested": last.CancelRequested,
		}
		if !last.EndedAt.IsZero() {
			m["ended_at"] = last.EndedAt.UTC().Format(time.RFC3339Nano)
		}
		lastScan = m
	}
	return map[string]any{
		"version":            s.version,
		"go_version":         runtime.Version(),
		"module_path":        modPath,
		"module_version":     modVer,
		"db_path":            s.dbPath,
		"probe_mode":         discovery.ProbeMode(),
		"probe_guidance":     discovery.ProbeGuidance(),
		"tcp_probe_profiles": discovery.TCPProbeProfiles(),
		"scan_status":        s.scanner.Status(),
		"concurrency_modes": map[string]int{
			"light":    12,
			"normal":   32,
			"thorough": 48,
			"deep":     48,
		},
		"last_scan":    lastScan,
		"audit_events": events,
	}, nil
}

func (s *Server) handleAbout(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lanternis — Diagnostics</title>
  <style>
    :root { --ln-bg:#f8f9fa; --ln-surface:#fff; --ln-text:#1a1a1a; --ln-muted:#6c757d; --ln-border:#dee2e6; --ln-accent:#0d6efd; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: var(--ln-bg); color: var(--ln-text); }
    main { max-width: 900px; margin: 0 auto; padding: 16px; }
    a { color: var(--ln-accent); }
    pre { background: var(--ln-surface); border: 1px solid var(--ln-border); border-radius: 4px; padding: 12px; overflow: auto; font-size: 13px; line-height: 1.4; white-space: pre-wrap; word-break: break-word; }
    .muted { color: var(--ln-muted); }
  </style>
</head>
<body>
  <main>
    <p><a href="/">← Back to scanner</a></p>
    <h1>Diagnostics</h1>
    <p class="muted">Read-only snapshot for troubleshooting. Same payload as <code>GET /api/diagnostics</code>.</p>
    <p><button type="button" id="supportExportBtn">Download redacted support bundle (JSON)</button> <span id="supportExportMsg" class="muted"></span></p>
    <p class="muted" style="font-size:14px;">The bundle includes versions, probe mode, scan/inventory <strong>counts</strong>, and audit <strong>event types</strong> — not full paths, audit payloads, or per-host IPs.</p>
    <pre id="diag">Loading…</pre>
  </main>
  <script>
    async function downloadSupportBundle() {
      const msg = document.getElementById("supportExportMsg");
      msg.textContent = "";
      try {
        const csrf = await fetch("/api/csrf").then((r) => r.json());
        const token = csrf.csrf_token || "";
        const res = await fetch("/api/support/export", {
          method: "POST",
          headers: { "X-CSRF-Token": token, "Content-Type": "application/json" },
          credentials: "same-origin",
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.error || ("HTTP " + res.status));
        }
        const blob = await res.blob();
        const cd = res.headers.get("Content-Disposition") || "";
        let name = "lanternis-support.json";
        const m = /filename="([^"]+)"/.exec(cd);
        if (m) name = m[1];
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
        msg.textContent = "Download started.";
      } catch (e) {
        msg.textContent = "Error: " + e.message;
      }
    }
    document.getElementById("supportExportBtn").addEventListener("click", downloadSupportBundle);
    fetch("/api/diagnostics")
      .then((r) => r.json())
      .then((data) => {
        document.getElementById("diag").textContent = JSON.stringify(data, null, 2);
      })
      .catch((e) => {
        document.getElementById("diag").textContent = "Error: " + e;
      });
  </script>
</body>
</html>`))
}
