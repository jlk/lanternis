package store

import (
	"context"
	"errors"
	"time"
)

// Finding is one versioned software identity tied to an exposed surface (vuln-oriented).
// Rows live in host_findings; CVE lookup uses this only when VulnReady is true.
type Finding struct {
	ID                int64     `json:"id"`
	Surface           string    `json:"surface"`
	VendorGuess       string    `json:"vendor_guess"`
	ProductGuess      string    `json:"product_guess"`
	VersionGuess      string    `json:"version_guess"`
	VersionConfidence string    `json:"version_confidence"`
	EvidenceKind      string    `json:"evidence_kind"`
	EvidenceDigest    string    `json:"evidence_digest"`
	CPECandidate      string    `json:"cpe_candidate,omitempty"`
	VulnReady         bool      `json:"vuln_ready"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (s *Store) ensureHostFindingsTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS host_findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_ip TEXT NOT NULL,
		surface TEXT NOT NULL,
		vendor_guess TEXT NOT NULL DEFAULT '',
		product_guess TEXT NOT NULL DEFAULT '',
		version_guess TEXT NOT NULL DEFAULT '',
		version_confidence TEXT NOT NULL DEFAULT 'unknown',
		evidence_kind TEXT NOT NULL DEFAULT '',
		evidence_digest TEXT NOT NULL DEFAULT '',
		cpe_candidate TEXT NOT NULL DEFAULT '',
		vuln_ready INTEGER NOT NULL DEFAULT 0,
		updated_at TEXT NOT NULL
	)`)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_host_findings_ip ON host_findings(host_ip)`)
	return err
}

// ReplaceHostFindings deletes all findings for host_ip and inserts the given rows (transactional).
func (s *Store) ReplaceHostFindings(ctx context.Context, hostIP string, findings []Finding) error {
	if hostIP == "" {
		return errors.New("empty host ip")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM host_findings WHERE host_ip = ?`, hostIP); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range findings {
		f := &findings[i]
		vr := 0
		if f.VulnReady {
			vr = 1
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO host_findings (
				host_ip, surface, vendor_guess, product_guess, version_guess,
				version_confidence, evidence_kind, evidence_digest, cpe_candidate, vuln_ready, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			hostIP,
			f.Surface,
			f.VendorGuess,
			f.ProductGuess,
			f.VersionGuess,
			f.VersionConfidence,
			f.EvidenceKind,
			f.EvidenceDigest,
			f.CPECandidate,
			vr,
			now,
		)
		if err != nil {
			return err
		}
		id, err := res.LastInsertId()
		if err == nil && id > 0 {
			f.ID = id
		}
		f.UpdatedAt, _ = time.Parse(time.RFC3339Nano, now)
	}
	return tx.Commit()
}

// ListFindingsByHost returns findings for one host, ordered by surface then id.
func (s *Store) ListFindingsByHost(ctx context.Context, hostIP string) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, surface, vendor_guess, product_guess, version_guess,
		       version_confidence, evidence_kind, evidence_digest, cpe_candidate, vuln_ready, updated_at
		FROM host_findings
		WHERE host_ip = ?
		ORDER BY surface ASC, id ASC`, hostIP)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var f Finding
		var updatedStr string
		var vr int
		if err := rows.Scan(
			&f.ID,
			&f.Surface,
			&f.VendorGuess,
			&f.ProductGuess,
			&f.VersionGuess,
			&f.VersionConfidence,
			&f.EvidenceKind,
			&f.EvidenceDigest,
			&f.CPECandidate,
			&vr,
			&updatedStr,
		); err != nil {
			return nil, err
		}
		f.VulnReady = vr != 0
		if t, e := time.Parse(time.RFC3339Nano, updatedStr); e == nil {
			f.UpdatedAt = t
		} else if t, e := time.Parse(time.RFC3339, updatedStr); e == nil {
			f.UpdatedAt = t
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
