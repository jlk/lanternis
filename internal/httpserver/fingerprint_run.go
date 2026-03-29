package httpserver

import (
	"context"
	"strings"
	"sync"

	"github.com/jlk/lanternis/internal/discovery/passive"
	"github.com/jlk/lanternis/internal/fingerprint"
	"github.com/jlk/lanternis/internal/store"
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
			rec, err := fingerprint.Build(ctx, h, hints, client, &fingerprint.BuildOptions{TCPProfile: tcpScanMode})
			if err != nil {
				return
			}
			label := fingerprint.DisplayLabel(rec, hints, h.IP)
			if strings.TrimSpace(label) == "" {
				label = strings.TrimSpace(h.Label)
			}
			if rec != nil {
				js, err := fingerprint.RecordJSON(rec)
				if err != nil {
					return
				}
				conf := fingerprint.ConfidenceFor(rec)
				_ = s.store.UpdateHostIdentity(ctx, h.IP, label, conf, js)
				return
			}
			// Build returned nil (no fingerprint signals yet); still apply mDNS/PTR-style names from hints.
			if strings.TrimSpace(label) != "" {
				_ = s.store.UpdateHostLabel(ctx, h.IP, label)
			}
		}()
	}
	wg.Wait()
}
