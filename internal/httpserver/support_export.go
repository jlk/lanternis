package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jlk/lanternis/internal/discovery"
)

// buildSupportBundle returns a redacted JSON-serializable snapshot for GitHub issues and support.
// It omits full filesystem paths, audit payloads, and per-host identifiers.
func (s *Server) buildSupportBundle(ctx context.Context) (map[string]any, error) {
	modPath, modVer := "", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		modPath = bi.Main.Path
		modVer = bi.Main.Version
	}

	last, err := s.store.LastScanRun(ctx)
	if err != nil {
		return nil, err
	}
	events, err := s.store.ListRecentAuditEvents(ctx, 50)
	if err != nil {
		return nil, err
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	suggested, err := s.store.SuggestedCIDR(ctx)
	if err != nil {
		return nil, err
	}
	firstDone, err := s.store.FirstRunComplete(ctx)
	if err != nil {
		return nil, err
	}
	nvdOK, err := s.store.NVDAPIKeyConfigured(ctx)
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

	byReach := map[string]int{}
	hintsRows := 0
	for _, h := range hosts {
		k := strings.ToLower(strings.TrimSpace(h.Reachability))
		if k == "" {
			k = "unknown"
		}
		byReach[k]++
		if len(h.RawHints) > 0 {
			hintsRows++
		}
	}

	auditRedacted := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		auditRedacted = append(auditRedacted, map[string]any{
			"id":         ev.ID,
			"ts":         ev.TS.UTC().Format(time.RFC3339Nano),
			"event_type": ev.EventType,
		})
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

	dbName := filepath.Base(s.dbPath)
	if dbName == "" || dbName == "." {
		dbName = "lanternis.db"
	}

	return map[string]any{
		"export_schema_version": 1,
		"generated_at_utc":      time.Now().UTC().Format(time.RFC3339Nano),
		"note":                  "Redacted: full DB path, audit payloads, and per-host IPs are omitted. Attach this file to GitHub issues as context.",
		"app": map[string]any{
			"version":        s.version,
			"go_version":     runtime.Version(),
			"module_path":    modPath,
			"module_version": modVer,
			"os_arch":        runtime.GOOS + "/" + runtime.GOARCH,
		},
		"probe": map[string]any{
			"probe_mode":         discovery.ProbeMode(),
			"probe_guidance":     discovery.ProbeGuidance(),
			"tcp_probe_profiles": discovery.TCPProbeProfiles(),
		},
		"paths": map[string]any{
			"db_filename": dbName,
		},
		"setup": map[string]any{
			"first_run_complete":           firstDone,
			"suggested_cidr":               suggested,
			"nvd_api_key_configured":       nvdOK,
			"web_enrichment_enabled":       webEnrich,
			"web_enrichment_provider":      webProv,
			"openai_api_key_configured":    openAIConfigured,
			"anthropic_api_key_configured": anthropicConfigured,
		},
		"scan_status": s.scanner.Status(),
		"concurrency_modes": map[string]int{
			"light":    12,
			"normal":   32,
			"thorough": 48,
			"deep":     48,
		},
		"last_scan": lastScan,
		"inventory_summary": map[string]any{
			"total_hosts":              len(hosts),
			"by_reachability":          byReach,
			"hosts_with_passive_hints": hintsRows,
		},
		"audit_events_redacted": auditRedacted,
	}, nil
}

func (s *Server) handleSupportExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	bundle, err := s.buildSupportBundle(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="lanternis-support-%s.json"`, time.Now().UTC().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(bundle)
}
