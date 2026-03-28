package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

const snapshotRetentionRuns = 10

// ScanHostSnapshot is one host row captured at end of a scan (CIDR-filtered).
type ScanHostSnapshot struct {
	IP           string   `json:"ip"`
	Reachability string   `json:"reachability"`
	OpenPorts    []string `json:"open_ports,omitempty"`
	Label        string   `json:"label"`
	Confidence   string   `json:"confidence"`
}

// ScanDiff is a CIDR-scoped comparison between two completed scan snapshots.
type ScanDiff struct {
	CurrentScanID   int64              `json:"current_scan_id"`
	PreviousScanID  int64              `json:"previous_scan_id,omitempty"`
	CIDR            string             `json:"cidr"`
	HostsAdded      []ScanHostSnapshot `json:"hosts_added"`
	HostsRemoved    []ScanHostSnapshot `json:"hosts_removed"`
	HostsChanged    []HostChange       `json:"hosts_changed"`
	NewOpenPorts    []PortOpenDelta    `json:"new_open_ports"`
}

// HostChange is a host present in both scans with some field delta.
type HostChange struct {
	IP           string   `json:"ip"`
	Reachability string   `json:"reachability,omitempty"`
	Label        string   `json:"label,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	OpenPorts    []string `json:"open_ports,omitempty"`
}

// PortOpenDelta lists ports that appeared since the previous snapshot for one IP.
type PortOpenDelta struct {
	IP    string   `json:"ip"`
	Ports []string `json:"ports"`
}

func (s *Store) ensureScanRunsCIDRColumn(ctx context.Context) error {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('scan_runs') WHERE name = 'cidr'`).Scan(&n)
	if err != nil {
		return fmt.Errorf("pragma scan_runs cidr: %w", err)
	}
	if n > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE scan_runs ADD COLUMN cidr TEXT NOT NULL DEFAULT ''`)
	return err
}

func (s *Store) ensureScanHostSnapshotsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS scan_host_snapshots (
	scan_id INTEGER NOT NULL,
	ip TEXT NOT NULL,
	reachability TEXT NOT NULL,
	open_ports_json TEXT NOT NULL DEFAULT '[]',
	label TEXT NOT NULL DEFAULT '',
	confidence TEXT NOT NULL DEFAULT 'unknown',
	PRIMARY KEY (scan_id, ip)
)`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_scan_host_snapshots_scan ON scan_host_snapshots(scan_id)`)
	return err
}

// ReplaceScanSnapshot stores CIDR-filtered host inventory for a completed scan.
func (s *Store) ReplaceScanSnapshot(ctx context.Context, scanID int64, cidr string, hosts []Host) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM scan_host_snapshots WHERE scan_id = ?`, scanID); err != nil {
		return err
	}

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO scan_host_snapshots (scan_id, ip, reachability, open_ports_json, label, confidence)
VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, h := range hosts {
		if !ipInCIDR(h.IP, cidr) {
			continue
		}
		portsJSON, err := marshalOpenPortsJSON(h.OpenPorts)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, scanID, h.IP, h.Reachability, portsJSON, h.Label, h.Confidence); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return s.pruneOldSnapshots(ctx)
}

func (s *Store) pruneOldSnapshots(ctx context.Context) error {
	// Keep snapshot rows only for the last snapshotRetentionRuns scan_ids.
	var ids []int64
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM scan_runs ORDER BY id DESC LIMIT ?`, snapshotRetentionRuns)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	// Build placeholders for NOT IN (...).
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	q := fmt.Sprintf(`DELETE FROM scan_host_snapshots WHERE scan_id NOT IN (%s)`, placeholders)
	_, err = s.db.ExecContext(ctx, q, args...)
	return err
}

// LoadScanSnapshot returns hosts in CIDR for a scan snapshot (sorted by IP).
func (s *Store) LoadScanSnapshot(ctx context.Context, scanID int64, cidr string) (map[string]ScanHostSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, reachability, open_ports_json, label, confidence
FROM scan_host_snapshots WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]ScanHostSnapshot)
	for rows.Next() {
		var sh ScanHostSnapshot
		var portsJSON string
		if err := rows.Scan(&sh.IP, &sh.Reachability, &portsJSON, &sh.Label, &sh.Confidence); err != nil {
			return nil, err
		}
		if !ipInCIDR(sh.IP, cidr) {
			continue
		}
		sh.OpenPorts = decodeOpenPortsJSON(portsJSON)
		sortOpenPortsNumeric(sh.OpenPorts)
		out[sh.IP] = sh
	}
	return out, rows.Err()
}

// LastTwoSnapshotScanIDs returns the two most recent scan_ids that have at least one snapshot row, newest first.
func (s *Store) LastTwoSnapshotScanIDs(ctx context.Context) (newest, older int64, ok bool, err error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT scan_id FROM scan_host_snapshots GROUP BY scan_id ORDER BY scan_id DESC LIMIT 2`)
	if err != nil {
		return 0, 0, false, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, 0, false, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, false, err
	}
	if len(ids) < 2 {
		if len(ids) == 1 {
			return ids[0], 0, false, nil
		}
		return 0, 0, false, nil
	}
	return ids[0], ids[1], true, nil
}

// ScanCIDR returns the cidr string stored for a scan run (may be empty for legacy rows).
func (s *Store) ScanCIDR(ctx context.Context, scanID int64) (string, error) {
	var c sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT cidr FROM scan_runs WHERE id = ?`, scanID).Scan(&c)
	if err != nil {
		return "", err
	}
	if c.Valid {
		return c.String, nil
	}
	return "", nil
}

// BuildScanDiff compares the newest snapshot to the previous; uses CIDR from the newer scan row.
func (s *Store) BuildScanDiff(ctx context.Context) (*ScanDiff, error) {
	newest, older, pair, err := s.LastTwoSnapshotScanIDs(ctx)
	if err != nil {
		return nil, err
	}
	if newest == 0 {
		return &ScanDiff{CIDR: ""}, nil
	}
	cidr, err := s.ScanCIDR(ctx, newest)
	if err != nil {
		return nil, err
	}
	if cidr == "" {
		cidr, _ = s.SuggestedCIDR(ctx)
	}
	if cidr == "" {
		cidr = defaultSetupCIDR
	}

	cur, err := s.LoadScanSnapshot(ctx, newest, cidr)
	if err != nil {
		return nil, err
	}

	diff := &ScanDiff{
		CurrentScanID: newest,
		CIDR:          cidr,
	}

	if !pair || older == 0 {
		return diff, nil
	}
	diff.PreviousScanID = older

	prev, err := s.LoadScanSnapshot(ctx, older, cidr)
	if err != nil {
		return nil, err
	}

	for ip, h := range cur {
		if _, ok := prev[ip]; !ok {
			diff.HostsAdded = append(diff.HostsAdded, h)
		}
	}
	for ip, h := range prev {
		if _, ok := cur[ip]; !ok {
			diff.HostsRemoved = append(diff.HostsRemoved, h)
		}
	}
	sort.Slice(diff.HostsAdded, func(i, j int) bool { return diff.HostsAdded[i].IP < diff.HostsAdded[j].IP })
	sort.Slice(diff.HostsRemoved, func(i, j int) bool { return diff.HostsRemoved[i].IP < diff.HostsRemoved[j].IP })

	for ip, a := range cur {
		b, ok := prev[ip]
		if !ok {
			continue
		}
		changed := !strings.EqualFold(a.Reachability, b.Reachability) ||
			a.Label != b.Label || a.Confidence != b.Confidence || !stringSliceEqual(a.OpenPorts, b.OpenPorts)
		if changed {
			diff.HostsChanged = append(diff.HostsChanged, HostChange{
				IP: ip, Reachability: a.Reachability, Label: a.Label, Confidence: a.Confidence,
				OpenPorts: append([]string(nil), a.OpenPorts...),
			})
		}
		newPorts := diffOpenPorts(b.OpenPorts, a.OpenPorts)
		if len(newPorts) > 0 {
			diff.NewOpenPorts = append(diff.NewOpenPorts, PortOpenDelta{IP: ip, Ports: newPorts})
		}
	}
	sort.Slice(diff.HostsChanged, func(i, j int) bool { return diff.HostsChanged[i].IP < diff.HostsChanged[j].IP })
	sort.Slice(diff.NewOpenPorts, func(i, j int) bool { return diff.NewOpenPorts[i].IP < diff.NewOpenPorts[j].IP })

	return diff, nil
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func diffOpenPorts(prev, cur []string) []string {
	prevSet := make(map[string]struct{})
	for _, p := range prev {
		prevSet[p] = struct{}{}
	}
	var out []string
	for _, p := range cur {
		if _, ok := prevSet[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

