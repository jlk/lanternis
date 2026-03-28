package fingerprint

import (
	"context"
	"testing"
	"time"

	"github.com/jlk/lanternis/internal/store"
)

func TestBuildOUIOnly(t *testing.T) {
	ctx := context.Background()
	h := store.Host{
		IP:           "192.168.1.10",
		Reachability: "reachable",
		OpenPorts:    nil,
		Confidence:   "unknown",
		LastSeen:     time.Now().UTC(),
	}
	hints := map[string]any{
		"arp": map[string]any{"mac": "00:11:22:33:44:55"},
	}
	// Prefix not in embedded DB → may return nil if no other signals
	rec, err := Build(ctx, h, hints, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec != nil {
		t.Logf("got record ladder=%d summary=%q", rec.LadderMax, rec.Summary)
	}

	hints["arp"] = map[string]any{"mac": "00:1A:11:00:00:01"} // Google OUI in embed
	rec2, err := Build(ctx, h, hints, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec2 == nil || rec2.LadderMax < 1 {
		t.Fatalf("expected OUI hit: %+v", rec2)
	}
	if rec2.Summary == "" {
		t.Fatal("expected summary from OUI")
	}
}
