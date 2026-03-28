package fingerprint

import (
	"context"
	"net"
	"strings"
	"time"
)

// LookupPTRFunc performs reverse DNS; tests may replace it to avoid flaky network I/O.
var LookupPTRFunc = defaultLookupPTR

func defaultLookupPTR(ctx context.Context, ip string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupAddr(ctx, ip)
}

// LookupPTR returns PTR names for ip (may be empty if NXDOMAIN / timeout / no resolver).
func LookupPTR(ctx context.Context, ip string) ([]string, error) {
	if LookupPTRFunc == nil {
		return nil, nil
	}
	names, err := LookupPTRFunc(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSuffix(strings.TrimSpace(n), ".")
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out, nil
}
