package passive

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jlk/lanternis/internal/store"
)

// ApplyDetail summarizes raw collection vs CIDR filtering (for debug logs).
type ApplyDetail struct {
	Collected int // rows from Collect* before CIDR filter
	InCIDR    int // entries inside CIDR (merge attempts)
}

// ApplyARPHints merges ARP cache entries that fall inside cidr into hosts.raw_hints_json under key "arp".
// Returns the number of IPs updated or inserted. Safe to run concurrently with active probing; scan UpsertHost does not clear raw_hints on update.
func ApplyARPHints(ctx context.Context, st *store.Store, cidr string) (merged int, detail ApplyDetail, err error) {
	entries, err := CollectARP(ctx)
	detail.Collected = len(entries)
	if err != nil {
		return 0, detail, err
	}
	n := 0
	for _, e := range entries {
		if !IPInCIDR(e.IP, cidr) {
			continue
		}
		detail.InCIDR++
		patch := map[string]any{
			"arp": map[string]any{
				"mac":    e.MAC,
				"source": e.Source,
			},
		}
		if err := st.MergeHostHints(ctx, e.IP, patch); err != nil {
			return n, detail, err
		}
		n++
	}
	return n, detail, nil
}

// ApplySSDPHints runs SSDP M-SEARCH and merges responses into raw_hints_json under "ssdp" for IPs in cidr.
// listenMax bounds the UDP read window; use 0 for the default (~3s).
func ApplySSDPHints(ctx context.Context, st *store.Store, cidr string, listenMax time.Duration) (merged int, detail ApplyDetail, err error) {
	entries, err := CollectSSDP(ctx, cidr, listenMax)
	detail.Collected = len(entries)
	if err != nil {
		return 0, detail, err
	}
	n := 0
	for _, e := range entries {
		if !IPInCIDR(e.IP, cidr) {
			continue
		}
		detail.InCIDR++
		existing, err := st.HostHints(ctx, e.IP)
		if err != nil {
			return n, detail, err
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
			return n, detail, err
		}
		n++
	}
	return n, detail, nil
}

// ApplyMDNSHints listens for mDNS traffic and merges hostnames into raw_hints_json under "mdns" for IPs in cidr.
// listenMax bounds the multicast listen window; use 0 for the default (~3.5s).
func ApplyMDNSHints(ctx context.Context, st *store.Store, cidr string, listenMax time.Duration) (merged int, detail ApplyDetail, err error) {
	entries, err := CollectMDNS(ctx, cidr, listenMax)
	detail.Collected = len(entries)
	if err != nil {
		return 0, detail, err
	}
	n := 0
	for _, e := range entries {
		if !IPInCIDR(e.IP, cidr) {
			continue
		}
		detail.InCIDR++
		existing, err := st.HostHints(ctx, e.IP)
		if err != nil {
			return n, detail, err
		}
		var mdnsObj map[string]any
		if x, ok := existing["mdns"].(map[string]any); ok {
			mdnsObj = x
		} else {
			mdnsObj = map[string]any{}
		}
		oldNames := stringSliceFromHint(mdnsObj, "names")
		oldServices := mdnsServicesFromHint(mdnsObj, "services")
		newServices := mdnsServicesFromEntries(e.Services)
		patch := map[string]any{
			"mdns": map[string]any{
				"names":    unionStrings(oldNames, e.Names),
				"services": unionMDNSServices(oldServices, newServices),
				"source":   "mdns_multicast",
			},
		}
		if err := st.MergeHostHints(ctx, e.IP, patch); err != nil {
			return n, detail, err
		}
		n++
	}
	return n, detail, nil
}

func mdnsServicesFromEntries(svcs []MDNSService) []map[string]any {
	if len(svcs) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(svcs))
	for _, s := range svcs {
		m := map[string]any{}
		if s.Type != "" {
			m["type"] = s.Type
		}
		if s.Instance != "" {
			m["instance"] = s.Instance
		}
		if s.Port > 0 {
			m["port"] = s.Port
		}
		if len(s.TXT) > 0 {
			txt := make([]any, 0, len(s.TXT))
			for _, t := range s.TXT {
				if strings.TrimSpace(t) == "" {
					continue
				}
				txt = append(txt, strings.TrimSpace(t))
			}
			if len(txt) > 0 {
				m["txt"] = txt
			}
		}
		if len(m) > 0 {
			out = append(out, m)
		}
	}
	return out
}

func mdnsServicesFromHint(m map[string]any, key string) []map[string]any {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, em)
	}
	return out
}

func unionMDNSServices(a, b []map[string]any) []any {
	seen := make(map[string]struct{})
	var out []any
	add := func(m map[string]any) {
		ty, _ := m["type"].(string)
		inst, _ := m["instance"].(string)
		port := 0
		switch x := m["port"].(type) {
		case int:
			port = x
		case int64:
			port = int(x)
		case float64:
			port = int(x)
		}
		txtKey := ""
		if t, ok := m["txt"].([]any); ok {
			parts := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					parts = append(parts, strings.TrimSpace(s))
				}
			}
			sort.Strings(parts)
			txtKey = strings.Join(parts, ";")
		}
		k := strings.TrimSpace(ty) + "|" + strings.TrimSpace(inst) + "|" + strconv.Itoa(port) + "|" + txtKey
		if k == "||0|" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, m)
	}
	for _, m := range a {
		add(m)
	}
	for _, m := range b {
		add(m)
	}
	return out
}
