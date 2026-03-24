package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Host struct {
	IP           string    `json:"ip"`
	Reachability string    `json:"reachability"`
	Label        string    `json:"label"`
	Confidence   string    `json:"confidence"`
	LastSeen     time.Time `json:"last_seen"`
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
		h.Reachability,
		h.Confidence,
		h.Label,
	)
	return err
}

func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, reachability, label, confidence, last_seen
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
		if err := rows.Scan(&h.IP, &h.Reachability, &h.Label, &h.Confidence, &lastSeen); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, lastSeen); err == nil {
			h.LastSeen = t
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
