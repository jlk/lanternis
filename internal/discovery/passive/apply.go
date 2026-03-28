package passive

import (
	"context"

	"github.com/jlk/lanternis/internal/store"
)

// ApplyARPHints merges ARP cache entries that fall inside cidr into hosts.raw_hints_json under key "arp".
// Returns the number of IPs updated or inserted. Safe to run concurrently with active probing; scan UpsertHost does not clear raw_hints on update.
func ApplyARPHints(ctx context.Context, st *store.Store, cidr string) (int, error) {
	entries, err := CollectARP(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !IPInCIDR(e.IP, cidr) {
			continue
		}
		patch := map[string]any{
			"arp": map[string]any{
				"mac":    e.MAC,
				"source": e.Source,
			},
		}
		if err := st.MergeHostHints(ctx, e.IP, patch); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
