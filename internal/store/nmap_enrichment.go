package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const appKeyNmapEnrichmentEnabled = "nmap_enrichment_enabled"

// NmapEnrichmentEnabled is true when the user opted in to optional Nmap-based fingerprint enrichment.
func (s *Store) NmapEnrichmentEnabled(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, appKeyNmapEnrichmentEnabled).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true"), nil
}

// SetNmapEnrichment persists the Nmap enrichment opt-in flag.
func (s *Store) SetNmapEnrichment(ctx context.Context, enabled bool) error {
	en := "0"
	if enabled {
		en = "1"
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, appKeyNmapEnrichmentEnabled, en)
	return err
}
