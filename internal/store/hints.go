package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func mergeJSONMaps(base, patch map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range base {
		out[k] = v
	}
	for k, v := range patch {
		if bm, ok := out[k].(map[string]any); ok {
			if pm, ok := v.(map[string]any); ok {
				out[k] = mergeJSONMaps(bm, pm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// HintsIndicatePassivePresence reports whether merged raw_hints contain ARP, mDNS, or SSDP
// evidence we surface in the UI (non-empty MAC, names, ST/USN lists, or server/location).
func HintsIndicatePassivePresence(m map[string]any) bool {
	if len(m) == 0 {
		return false
	}
	if arp, ok := m["arp"].(map[string]any); ok {
		if mac, ok := arp["mac"].(string); ok && strings.TrimSpace(mac) != "" {
			return true
		}
	}
	if mdns, ok := m["mdns"].(map[string]any); ok {
		if hintStringSliceNonEmpty(mdns, "names") {
			return true
		}
		if hintAnySliceNonEmpty(mdns, "services") {
			return true
		}
	}
	if ssdp, ok := m["ssdp"].(map[string]any); ok {
		if hintStringSliceNonEmpty(ssdp, "st_types") || hintStringSliceNonEmpty(ssdp, "usns") {
			return true
		}
		if srv, ok := ssdp["server"].(string); ok && strings.TrimSpace(srv) != "" {
			return true
		}
		if loc, ok := ssdp["location"].(string); ok && strings.TrimSpace(loc) != "" {
			return true
		}
	}
	return false
}

func hintStringSliceNonEmpty(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	default:
		return false
	}
}

func hintAnySliceNonEmpty(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case []any:
		return len(x) > 0
	default:
		return false
	}
}

// HostHints returns the decoded raw_hints_json object for ip, or an empty map if none / missing row.
func (s *Store) HostHints(ctx context.Context, ip string) (map[string]any, error) {
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT raw_hints_json FROM hosts WHERE ip = ?`, ip).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("host hints: %w", err)
	}
	out := map[string]any{}
	if raw.Valid && raw.String != "" && raw.String != "{}" {
		if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
			return nil, fmt.Errorf("decode raw_hints_json: %w", err)
		}
	}
	return out, nil
}

// MergeHostHints merges patch into hosts.raw_hints_json (JSON object merge for nested maps).
// If the host row does not exist, inserts a minimal row; reachability is observed when merged
// hints include ARP/mDNS/SSDP evidence, otherwise unknown. Existing rows with reachability unknown
// are promoted to observed when merged hints qualify.
func (s *Store) MergeHostHints(ctx context.Context, ip string, patch map[string]any) error {
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT raw_hints_json FROM hosts WHERE ip = ?`, ip).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	existing := map[string]any{}
	if raw.Valid && raw.String != "" {
		_ = json.Unmarshal([]byte(raw.String), &existing)
	}
	merged := mergeJSONMaps(existing, patch)
	b, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET raw_hints_json = ? WHERE ip = ?`, string(b), ip)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		if HintsIndicatePassivePresence(merged) {
			_, err = s.db.ExecContext(ctx,
				`UPDATE hosts SET reachability = 'observed' WHERE ip = ? AND reachability = 'unknown'`,
				ip)
			if err != nil {
				return err
			}
		}
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	reach := "unknown"
	if HintsIndicatePassivePresence(merged) {
		reach = "observed"
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO hosts (ip, last_seen, reachability, raw_hints_json, confidence, label)
		VALUES (?, ?, ?, ?, 'unknown', '')`,
		ip, now, reach, string(b))
	return err
}
