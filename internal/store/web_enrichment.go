package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const (
	appKeyWebEnrichmentEnabled  = "web_enrichment_enabled"
	appKeyWebEnrichmentProvider = "web_enrichment_provider"
	appKeyOpenAIAPIKey          = "openai_api_key"
	appKeyAnthropicAPIKey       = "anthropic_api_key"
)

// WebEnrichmentProvider returns "openai" or "anthropic". Default is openai when unset.
func (s *Store) WebEnrichmentProvider(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, appKeyWebEnrichmentProvider).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "openai", nil
	}
	if err != nil {
		return "", err
	}
	if strings.ToLower(strings.TrimSpace(v)) == "anthropic" {
		return "anthropic", nil
	}
	return "openai", nil
}

// WebEnrichmentEnabled reports whether the user opted in to internet-assisted name hints.
func (s *Store) WebEnrichmentEnabled(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, appKeyWebEnrichmentEnabled).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true"), nil
}

// OpenAIAPIKey returns the stored OpenAI API key, or "" if unset. For server use only; never log.
func (s *Store) OpenAIAPIKey(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, appKeyOpenAIAPIKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

// OpenAIAPIKeyConfigured is true when a non-empty key is stored.
func (s *Store) OpenAIAPIKeyConfigured(ctx context.Context) (bool, error) {
	k, err := s.OpenAIAPIKey(ctx)
	return k != "", err
}

// AnthropicAPIKey returns the stored Anthropic API key, or "" if unset. For server use only; never log.
func (s *Store) AnthropicAPIKey(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, appKeyAnthropicAPIKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

// AnthropicAPIKeyConfigured is true when a non-empty key is stored.
func (s *Store) AnthropicAPIKeyConfigured(ctx context.Context) (bool, error) {
	k, err := s.AnthropicAPIKey(ctx)
	return k != "", err
}

// WebEnrichmentUpdate persists opt-in, provider, and API keys.
// Provider: "openai" or "anthropic"; empty string leaves the stored provider unchanged.
// Clear* removes the corresponding key; a non-empty key field replaces the stored key (after clear, if any).
type WebEnrichmentUpdate struct {
	Enabled           bool
	Provider          string
	OpenAIKey         string
	AnthropicKey      string
	ClearOpenAIKey    bool
	ClearAnthropicKey bool
}

// SetWebEnrichment applies WebEnrichmentUpdate in a single transaction.
func (s *Store) SetWebEnrichment(ctx context.Context, u WebEnrichmentUpdate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	en := "0"
	if u.Enabled {
		en = "1"
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, appKeyWebEnrichmentEnabled, en); err != nil {
		return err
	}
	if p := strings.ToLower(strings.TrimSpace(u.Provider)); p != "" {
		if p != "openai" && p != "anthropic" {
			p = "openai"
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, appKeyWebEnrichmentProvider, p); err != nil {
			return err
		}
	}
	if u.ClearOpenAIKey {
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_kv WHERE key = ?`, appKeyOpenAIAPIKey); err != nil {
			return err
		}
	} else if k := strings.TrimSpace(u.OpenAIKey); k != "" {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, appKeyOpenAIAPIKey, k); err != nil {
			return err
		}
	}
	if u.ClearAnthropicKey {
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_kv WHERE key = ?`, appKeyAnthropicAPIKey); err != nil {
			return err
		}
	} else if k := strings.TrimSpace(u.AnthropicKey); k != "" {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, appKeyAnthropicAPIKey, k); err != nil {
			return err
		}
	}
	return tx.Commit()
}
