package store

import (
	"context"
	"testing"
	"time"
)

func TestStoreUpsertAndListHosts(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Second)
	h := Host{
		IP:           "192.168.1.10",
		Reachability: "reachable",
		Label:        "router",
		Confidence:   "high",
		LastSeen:     now,
	}
	if err := st.UpsertHost(ctx, h); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	hosts, err := st.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].IP != h.IP || hosts[0].Reachability != h.Reachability || hosts[0].Label != h.Label || hosts[0].Confidence != h.Confidence {
		t.Fatalf("unexpected host row: %+v", hosts[0])
	}
}

func TestLastScanRunEmpty(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()
	run, err := st.LastScanRun(ctx)
	if err != nil {
		t.Fatalf("LastScanRun: %v", err)
	}
	if run != nil {
		t.Fatalf("expected nil last scan on empty DB")
	}
}

func TestFirstRunCompleteLegacyHosts(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	done, err := st.FirstRunComplete(ctx)
	if err != nil {
		t.Fatalf("FirstRunComplete: %v", err)
	}
	if done {
		t.Fatal("expected first run incomplete on empty DB")
	}
	now := time.Now().UTC()
	if err := st.UpsertHost(ctx, Host{
		IP: "10.0.0.1", Reachability: "unknown", Label: "", Confidence: "unknown", LastSeen: now,
	}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	done, err = st.FirstRunComplete(ctx)
	if err != nil {
		t.Fatalf("FirstRunComplete: %v", err)
	}
	if !done {
		t.Fatal("expected legacy DB with hosts to count as setup-complete")
	}
}

func TestStoreScanRunAndCancelFlag(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	id, err := st.InsertScanRun(ctx, "normal")
	if err != nil {
		t.Fatalf("InsertScanRun: %v", err)
	}

	// Mark ended with cancel requested.
	if err := st.MarkScanEnded(ctx, id, true); err != nil {
		t.Fatalf("MarkScanEnded: %v", err)
	}

	// Query raw to avoid adding extra exported methods for just one test.
	row, err := st.dbQueryRow(ctx, `SELECT ended_at, cancel_requested FROM scan_runs WHERE id = ?`, id)
	if err != nil {
		t.Fatalf("query scan_runs: %v", err)
	}
	if row.cancelRequested != 1 {
		t.Fatalf("expected cancel_requested=1, got %d", row.cancelRequested)
	}
	if row.endedAt.IsZero() {
		t.Fatalf("expected ended_at to be set")
	}
}

func mustTestStore(t *testing.T, ctx context.Context) (*Store, func()) {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/test.db"
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st, func() { _ = st.Close() }
}

// dbQueryRow is a tiny test-only helper by using the unexported db field.
func (s *Store) dbQueryRow(ctx context.Context, query string, args ...any) (struct {
	endedAt          time.Time
	cancelRequested int
}, error) {
	type scanRow struct {
		endedAtStr      string
		cancelRequested int
	}
	var r scanRow
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&r.endedAtStr, &r.cancelRequested); err != nil {
		return struct {
			endedAt          time.Time
			cancelRequested int
		}{}, err
	}
	endedAt, _ := time.Parse(time.RFC3339Nano, r.endedAtStr)
	return struct {
		endedAt          time.Time
		cancelRequested int
	}{endedAt: endedAt, cancelRequested: r.cancelRequested}, nil
}

