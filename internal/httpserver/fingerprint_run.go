package httpserver

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jlk/lanternis/internal/discovery/passive"
	"github.com/jlk/lanternis/internal/fingerprint"
	"github.com/jlk/lanternis/internal/store"
	"github.com/jlk/lanternis/internal/webenrich"
)

// applyFingerprints runs L1–L4 fingerprinting for hosts inside cidr (parallel, bounded).
// tcpScanMode is the scan mode (light/normal/thorough); forwarded to fingerprint.Build for probe depth.
func (s *Server) applyFingerprints(ctx context.Context, cidr string, hosts []store.Host, tcpScanMode string) {
	client := fingerprint.DefaultHTTPClient()
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, host := range hosts {
		if !passive.IPInCIDR(host.IP, cidr) {
			continue
		}
		h := host
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hints, err := s.store.HostHints(ctx, h.IP)
			if err != nil {
				return
			}
			rec, err := fingerprint.Build(ctx, h, hints, client, &fingerprint.BuildOptions{
				TCPProfile:    tcpScanMode,
				DeviceAliases: s.deviceAliases,
			})
			if err != nil {
				return
			}
			label := fingerprint.DisplayLabel(rec, hints, h.IP)
			if strings.TrimSpace(label) == "" {
				label = strings.TrimSpace(h.Label)
			}
			if rec != nil {
				if on, _ := s.store.WebEnrichmentEnabled(ctx); on {
					prov, _ := s.store.WebEnrichmentProvider(ctx)
					var key string
					switch prov {
					case "anthropic":
						key, _ = s.store.AnthropicAPIKey(ctx)
					default:
						key, _ = s.store.OpenAIAPIKey(ctx)
					}
					if key != "" && s.webEnrichLimit != nil {
						// Wait for an RPM slot (large LANs can queue many hosts; do not use the HTTP timeout for this).
						queueCtx, queueCancel := context.WithTimeout(ctx, 3*time.Minute)
						waitErr := s.webEnrichLimit.Wait(queueCtx)
						queueCancel()
						if waitErr != nil {
							if s.debug {
								s.debugf("web enrich ip=%s provider=%s: skipped waiting for rate limit slot: %v", h.IP, prov, waitErr)
							}
						} else {
							enrichCtx, enrichCancel := context.WithTimeout(ctx, 13*time.Second)
							nBefore := webLLMInferenceCount(rec)
							err := webenrich.EnrichRecord(enrichCtx, rec, hints, prov, key)
							enrichCancel()
							if s.debug {
								if err != nil {
									s.debugf("web enrich ip=%s provider=%s: %v", h.IP, prov, err)
								} else if webLLMInferenceCount(rec) > nBefore {
									s.debugf("web enrich ip=%s provider=%s: added web_llm name hint", h.IP, prov)
								} else {
									s.debugf("web enrich ip=%s provider=%s: no hint (not enough name text, model empty reply, or parse miss)", h.IP, prov)
								}
							}
						}
					}
				}
				js, err := fingerprint.RecordJSON(rec)
				if err != nil {
					return
				}
				conf := fingerprint.ConfidenceFor(rec)
				_ = s.store.UpdateHostIdentity(ctx, h.IP, label, conf, js)
				_ = s.store.ReplaceHostFindings(ctx, h.IP, fingerprint.FindingsFromRecord(rec))
				return
			}
			// Build returned nil (no fingerprint signals yet); still apply mDNS/PTR-style names from hints.
			if strings.TrimSpace(label) != "" {
				_ = s.store.UpdateHostLabel(ctx, h.IP, label)
			}
			_ = s.store.ReplaceHostFindings(ctx, h.IP, nil)
		}()
	}
	wg.Wait()
}

func webLLMInferenceCount(rec *fingerprint.Record) int {
	if rec == nil {
		return 0
	}
	n := 0
	for _, inf := range rec.Inferences {
		if inf.Source == "web_llm" {
			n++
		}
	}
	return n
}
