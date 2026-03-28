package httpserver

import (
	"context"
	"sync"
	"time"

	"github.com/jlk/lanternis/internal/discovery/passive"
)

// BackgroundPassiveConfig controls periodic SSDP/mDNS hint collection while the server runs (ARP is not repeated).
// Interval <= 0 disables the loop. Window is the listen duration passed to each collector; SSDP and mDNS run in parallel each tick.
type BackgroundPassiveConfig struct {
	Interval time.Duration // e.g. 1m; 0 = disabled
	Window   time.Duration // per collector; 0 = DefaultBackgroundPassiveWindow
}

// DefaultBackgroundPassiveWindow is used when BackgroundPassiveConfig.Window <= 0.
const DefaultBackgroundPassiveWindow = 10 * time.Second

// RunBackgroundPassive starts a goroutine that every Interval runs SSDP and mDNS against SuggestedCIDR after first-run setup.
// Cancel ctx to stop (e.g. on process shutdown). No-op if Interval <= 0.
func (s *Server) RunBackgroundPassive(ctx context.Context, cfg BackgroundPassiveConfig) {
	if cfg.Interval <= 0 {
		return
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultBackgroundPassiveWindow
	}
	go s.backgroundPassiveLoop(ctx, cfg.Interval, window)
}

func (s *Server) backgroundPassiveLoop(ctx context.Context, interval, window time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runBackgroundPassiveOnce(window)
		}
	}
}

func (s *Server) runBackgroundPassiveOnce(window time.Duration) {
	ctx := context.Background()
	done, err := s.store.FirstRunComplete(ctx)
	if err != nil || !done {
		return
	}
	cidr, err := s.store.SuggestedCIDR(ctx)
	if err != nil || cidr == "" {
		return
	}
	var ssdpN, mdnsN int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _, err := passive.ApplySSDPHints(ctx, s.store, cidr, window)
		if err != nil {
			s.logger.Printf("background passive SSDP: %v", err)
			return
		}
		ssdpN = n
	}()
	go func() {
		defer wg.Done()
		n, _, err := passive.ApplyMDNSHints(ctx, s.store, cidr, window)
		if err != nil {
			s.logger.Printf("background passive mDNS: %v", err)
			return
		}
		mdnsN = n
	}()
	wg.Wait()
	s.logger.Printf("background passive cidr=%s ssdp_merged=%d mdns_merged=%d window=%s", cidr, ssdpN, mdnsN, window.Round(time.Millisecond))
}
