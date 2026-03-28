package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Host struct {
	IP           string          `json:"ip"`
	Reachability string          `json:"reachability"`
	Label        string          `json:"label"`
	Confidence   string          `json:"confidence"`
	LastSeen     time.Time       `json:"last_seen"`
	RawHints     json.RawMessage `json:"raw_hints,omitempty"`
}

type ScanRun struct {
	ID              int64     `json:"id"`
	StartedAt       time.Time `json:"started_at"`
	EndedAt         time.Time `json:"ended_at,omitempty"`
	Mode            string    `json:"mode"`
	CancelRequested bool      `json:"cancel_requested"`
}

func Open(ctx context.Context, path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS scan_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at TEXT NOT NULL,
			ended_at TEXT,
			mode TEXT NOT NULL,
			cancel_requested INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS hosts (
			ip TEXT PRIMARY KEY,
			last_seen TEXT NOT NULL,
			reachability TEXT NOT NULL,
			raw_hints_json TEXT NOT NULL DEFAULT '{}',
			confidence TEXT NOT NULL,
			fingerprint_blob TEXT NOT NULL DEFAULT '',
			label TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS intel_cache (
			cache_key TEXT PRIMARY KEY,
			payload_json TEXT NOT NULL,
			fetched_at TEXT NOT NULL,
			ttl_class TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);`,
		`CREATE TABLE IF NOT EXISTS app_kv (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) InsertScanRun(ctx context.Context, mode string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `INSERT INTO scan_runs (started_at, mode) VALUES (?, ?)`, now, mode)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) MarkScanEnded(ctx context.Context, id int64, cancelRequested bool) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cancel := 0
	if cancelRequested {
		cancel = 1
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET ended_at = ?, cancel_requested = ? WHERE id = ?`,
		now,
		cancel,
		id,
	)
	return err
}

func (s *Store) UpsertHost(ctx context.Context, h Host) error {
	reach := h.Reachability
	if strings.EqualFold(reach, "unknown") {
		hints, err := s.HostHints(ctx, h.IP)
		if err == nil && HintsIndicatePassivePresence(hints) {
			reach = "observed"
		}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hosts (ip, last_seen, reachability, confidence, label)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			last_seen = excluded.last_seen,
			reachability = excluded.reachability,
			confidence = excluded.confidence,
			label = excluded.label
	`,
		h.IP,
		h.LastSeen.UTC().Format(time.RFC3339Nano),
		reach,
		h.Confidence,
		h.Label,
	)
	return err
}

func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, reachability, label, confidence, last_seen, raw_hints_json
		FROM hosts
		ORDER BY ip ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Host, 0)
	for rows.Next() {
		var h Host
		var lastSeen string
		var rawHints sql.NullString
		if err := rows.Scan(&h.IP, &h.Reachability, &h.Label, &h.Confidence, &lastSeen, &rawHints); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, lastSeen); err == nil {
			h.LastSeen = t
		}
		if rawHints.Valid && rawHints.String != "" && rawHints.String != "{}" {
			h.RawHints = json.RawMessage(rawHints.String)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) InsertAuditEvent(ctx context.Context, eventType string, payloadJSON string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_events (ts, event_type, payload_json) VALUES (?, ?, ?)`,
		now,
		eventType,
		payloadJSON,
	)
	return err
}

const defaultSetupCIDR = "192.168.1.0/24"

// FirstRunComplete returns true after the user has acknowledged the first-run trust screen,
// or if the database already contains evidence of prior use (legacy installs).
func (s *Store) FirstRunComplete(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, "first_run_completed_at").Scan(&v)
	if err == nil && v != "" {
		return true, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_runs`).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// SuggestedCIDR returns the saved default CIDR for the UI, or a safe placeholder.
func (s *Store) SuggestedCIDR(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_kv WHERE key = ?`, "default_cidr").Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultSetupCIDR, nil
	}
	if err != nil {
		return "", err
	}
	if v == "" {
		return defaultSetupCIDR, nil
	}
	return v, nil
}

// CompleteFirstRun records acknowledgment and the chosen home-network CIDR.
func (s *Store) CompleteFirstRun(ctx context.Context, cidr string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, "first_run_completed_at", now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO app_kv (key, value) VALUES (?, ?)`, "default_cidr", cidr); err != nil {
		return err
	}
	return tx.Commit()
}

// AuditEvent is a row from audit_events (read-only diagnostics).
type AuditEvent struct {
	ID          int64     `json:"id"`
	TS          time.Time `json:"ts"`
	EventType   string    `json:"event_type"`
	PayloadJSON string    `json:"payload_json"`
}

// LastScanRun returns the most recent scan_runs row, or nil if none.
func (s *Store) LastScanRun(ctx context.Context) (*ScanRun, error) {
	var sr ScanRun
	var startedStr string
	var ended sql.NullString
	var cancel int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, started_at, ended_at, mode, cancel_requested FROM scan_runs ORDER BY id DESC LIMIT 1`,
	).Scan(&sr.ID, &startedStr, &ended, &sr.Mode, &cancel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sr.StartedAt, err = time.Parse(time.RFC3339Nano, startedStr)
	if err != nil {
		sr.StartedAt, _ = time.Parse(time.RFC3339, startedStr)
	}
	if ended.Valid && ended.String != "" {
		t, e := time.Parse(time.RFC3339Nano, ended.String)
		if e != nil {
			t, _ = time.Parse(time.RFC3339, ended.String)
		}
		sr.EndedAt = t
	}
	sr.CancelRequested = cancel != 0
	return &sr, nil
}

// ListRecentAuditEvents returns the newest audit rows (newest first), capped at 100.
func (s *Store) ListRecentAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, event_type, payload_json FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEvent, 0)
	for rows.Next() {
		var ev AuditEvent
		var tsStr string
		if err := rows.Scan(&ev.ID, &tsStr, &ev.EventType, &ev.PayloadJSON); err != nil {
			return nil, err
		}
		ts, e := time.Parse(time.RFC3339Nano, tsStr)
		if e != nil {
			ts, _ = time.Parse(time.RFC3339, tsStr)
		}
		ev.TS = ts
		out = append(out, ev)
	}
	return out, rows.Err()
}
