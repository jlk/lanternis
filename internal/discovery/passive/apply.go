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

// ApplySSDPHints runs SSDP M-SEARCH and merges responses into raw_hints_json under "ssdp" for IPs in cidr.
func ApplySSDPHints(ctx context.Context, st *store.Store, cidr string) (int, error) {
	entries, err := CollectSSDP(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !IPInCIDR(e.IP, cidr) {
			continue
		}
		existing, err := st.HostHints(ctx, e.IP)
		if err != nil {
			return n, err
		}
		var ssdpObj map[string]any
		if x, ok := existing["ssdp"].(map[string]any); ok {
			ssdpObj = x
		} else {
			ssdpObj = map[string]any{}
		}
		oldST := stringSliceFromHint(ssdpObj, "st_types")
		oldUSN := stringSliceFromHint(ssdpObj, "usns")
		ssdpPatch := map[string]any{
			"st_types": unionStrings(oldST, e.STTypes),
			"usns":     unionStrings(oldUSN, e.USNs),
			"source":   "ssdp_msearch",
		}
		if e.Server != "" {
			ssdpPatch["server"] = e.Server
		}
		if e.Location != "" {
			ssdpPatch["location"] = e.Location
		}
		patch := map[string]any{"ssdp": ssdpPatch}
		if err := st.MergeHostHints(ctx, e.IP, patch); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ApplyMDNSHints listens for mDNS traffic and merges hostnames into raw_hints_json under "mdns" for IPs in cidr.
func ApplyMDNSHints(ctx context.Context, st *store.Store, cidr string) (int, error) {
	entries, err := CollectMDNS(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !IPInCIDR(e.IP, cidr) {
			continue
		}
		existing, err := st.HostHints(ctx, e.IP)
		if err != nil {
			return n, err
		}
		var mdnsObj map[string]any
		if x, ok := existing["mdns"].(map[string]any); ok {
			mdnsObj = x
		} else {
			mdnsObj = map[string]any{}
		}
		oldNames := stringSliceFromHint(mdnsObj, "names")
		patch := map[string]any{
			"mdns": map[string]any{
				"names":  unionStrings(oldNames, e.Names),
				"source": "mdns_multicast",
			},
		}
		if err := st.MergeHostHints(ctx, e.IP, patch); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
