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
	webEnrich, err := s.store.WebEnrichmentEnabled(ctx)
	if err != nil {
		return nil, err
	}
	openAIConfigured, err := s.store.OpenAIAPIKeyConfigured(ctx)
	if err != nil {
		return nil, err
	}
	webProv, err := s.store.WebEnrichmentProvider(ctx)
	if err != nil {
		return nil, err
	}
	anthropicConfigured, err := s.store.AnthropicAPIKeyConfigured(ctx)
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
		"web_enrichment_enabled":          webEnrich,
		"web_enrichment_provider":         webProv,
		"openai_api_key_configured":       openAIConfigured,
		"anthropic_api_key_configured":    anthropicConfigured,
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
    <h2 style="font-size:18px;margin-top:28px;">Internet-assisted name hints</h2>
    <p class="muted" style="font-size:14px;">Optional: send <strong>hostname fragments and device-class hints</strong> (not your IP) to <a href="https://platform.openai.com/" target="_blank" rel="noopener noreferrer">OpenAI</a> or <a href="https://console.anthropic.com/" target="_blank" rel="noopener noreferrer">Anthropic (Claude)</a> using your API key. Suggestions appear as <code>web_llm</code> under Name hints after a scan. Keys stay in your local DB only.</p>
    <p><label class="setup-check" style="display:flex;gap:8px;align-items:center;"><input type="checkbox" id="weEnabled" /> Enable internet-assisted name hints</label></p>
    <p><label>Provider <select id="weProvider" style="min-width:200px;"><option value="openai">OpenAI</option><option value="anthropic">Anthropic (Claude)</option></select></label></p>
    <p><label>OpenAI API key <input type="password" id="weKeyOpenAI" autocomplete="off" style="min-width:260px;" /></label></p>
    <p><label class="setup-check" style="display:flex;gap:8px;align-items:center;"><input type="checkbox" id="weClearOpenAI" /> Remove stored OpenAI key</label></p>
    <p><label>Anthropic API key <input type="password" id="weKeyAnthropic" autocomplete="off" style="min-width:260px;" /></label></p>
    <p><label class="setup-check" style="display:flex;gap:8px;align-items:center;"><input type="checkbox" id="weClearAnthropic" /> Remove stored Anthropic key</label></p>
    <p><button type="button" id="weSave">Save settings</button> <span id="weMsg" class="muted"></span></p>
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
    async function loadWebEnrich() {
      try {
        const d = await fetch("/api/settings/web-enrichment").then((r) => r.json());
        document.getElementById("weEnabled").checked = !!d.enabled;
        const prov = (d.provider === "anthropic") ? "anthropic" : "openai";
        document.getElementById("weProvider").value = prov;
        document.getElementById("weKeyOpenAI").value = "";
        document.getElementById("weKeyOpenAI").placeholder = d.openai_api_key_configured ? "Key on file — enter to replace" : "sk-…";
        document.getElementById("weKeyAnthropic").value = "";
        document.getElementById("weKeyAnthropic").placeholder = d.anthropic_api_key_configured ? "Key on file — enter to replace" : "sk-ant-…";
        document.getElementById("weClearOpenAI").checked = false;
        document.getElementById("weClearAnthropic").checked = false;
      } catch (e) { /* setup not done */ }
    }
    document.getElementById("weSave").addEventListener("click", async function () {
      const msg = document.getElementById("weMsg");
      msg.textContent = "";
      try {
        const csrf = await fetch("/api/csrf").then((r) => r.json());
        const token = csrf.csrf_token || "";
        const res = await fetch("/api/settings/web-enrichment", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
          credentials: "same-origin",
          body: JSON.stringify({
            enabled: document.getElementById("weEnabled").checked,
            provider: document.getElementById("weProvider").value,
            openai_api_key: document.getElementById("weKeyOpenAI").value.trim(),
            anthropic_api_key: document.getElementById("weKeyAnthropic").value.trim(),
            clear_openai_key: document.getElementById("weClearOpenAI").checked,
            clear_anthropic_key: document.getElementById("weClearAnthropic").checked
          })
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.error || ("HTTP " + res.status));
        }
        msg.textContent = "Saved.";
        await loadWebEnrich();
      } catch (e) {
        msg.textContent = "Error: " + e.message;
      }
    });
    loadWebEnrich();
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
