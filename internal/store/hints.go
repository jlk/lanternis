package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
// If the host row does not exist, inserts a minimal row with reachability unknown.
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
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO hosts (ip, last_seen, reachability, raw_hints_json, confidence, label)
		VALUES (?, ?, 'unknown', ?, 'unknown', '')`,
		ip, now, string(b))
	return err
}
