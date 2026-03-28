package httpserver

import (
	"context"
	"sync"

	"github.com/jlk/lanternis/internal/discovery/passive"
	"github.com/jlk/lanternis/internal/fingerprint"
	"github.com/jlk/lanternis/internal/store"
)

// applyFingerprints runs L1–L4 fingerprinting for hosts inside cidr (parallel, bounded).
func (s *Server) applyFingerprints(ctx context.Context, cidr string, hosts []store.Host) {
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
			rec, err := fingerprint.Build(ctx, h, hints, client)
			if err != nil || rec == nil {
				return
			}
			js, err := fingerprint.RecordJSON(rec)
			if err != nil {
				return
			}
			label := rec.Summary
			if label == "" {
				label = h.Label
			}
			conf := fingerprint.ConfidenceFor(rec)
			_ = s.store.UpdateHostIdentity(ctx, h.IP, label, conf, js)
		}()
	}
	wg.Wait()
}
