package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestHintsIndicatePassivePresence(t *testing.T) {
	if !HintsIndicatePassivePresence(map[string]any{"arp": map[string]any{"mac": "aa:bb:cc:dd:ee:01"}}) {
		t.Fatal("expected arp mac")
	}
	if HintsIndicatePassivePresence(map[string]any{"arp": map[string]any{"mac": ""}}) {
		t.Fatal("empty mac should not count")
	}
	if !HintsIndicatePassivePresence(map[string]any{"mdns": map[string]any{"names": []any{"x.local"}}}) {
		t.Fatal("expected mdns names")
	}
	if !HintsIndicatePassivePresence(map[string]any{"ssdp": map[string]any{"st_types": []any{"upnp:rootdevice"}}}) {
		t.Fatal("expected ssdp st_types")
	}
	if HintsIndicatePassivePresence(map[string]any{}) {
		t.Fatal("empty map")
	}
}

func TestHostHintsEmpty(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()
	h, err := st.HostHints(ctx, "10.0.0.99")
	if err != nil {
		t.Fatalf("HostHints: %v", err)
	}
	if len(h) != 0 {
		t.Fatalf("expected empty map, got %v", h)
	}
}

func TestMergeHostHints(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	ip := "10.0.0.7"
	patch1 := map[string]any{
		"arp": map[string]any{"mac": "aa:bb:cc:dd:ee:01", "source": "linux_proc"},
	}
	if err := st.MergeHostHints(ctx, ip, patch1); err != nil {
		t.Fatalf("MergeHostHints first: %v", err)
	}
	patch2 := map[string]any{
		"arp": map[string]any{"mac": "aa:bb:cc:dd:ee:02"},
	}
	if err := st.MergeHostHints(ctx, ip, patch2); err != nil {
		t.Fatalf("MergeHostHints second: %v", err)
	}
	hosts, err := st.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	var m map[string]any
	if err := json.Unmarshal(hosts[0].RawHints, &m); err != nil {
		t.Fatalf("unmarshal raw_hints: %v", err)
	}
	arp, _ := m["arp"].(map[string]any)
	if arp == nil {
		t.Fatal("expected arp object in raw_hints")
	}
	if arp["mac"] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("expected merged mac, got %v", arp["mac"])
	}
	if arp["source"] != "linux_proc" {
		t.Fatalf("expected nested merge to keep source, got %v", arp["source"])
	}
	if hosts[0].Reachability != "observed" {
		t.Fatalf("expected reachability observed when hints include ARP, got %q", hosts[0].Reachability)
	}

	// UpsertHost must not wipe hints.
	now := time.Now().UTC()
	if err := st.UpsertHost(ctx, Host{
		IP: ip, Reachability: "reachable", Label: "x", Confidence: "high", LastSeen: now,
	}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	hosts2, err := st.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts after upsert: %v", err)
	}
	if len(hosts2) != 1 || len(hosts2[0].RawHints) == 0 {
		t.Fatalf("expected raw_hints preserved after UpsertHost, got %+v", hosts2)
	}
}

func TestUpsertHostUnknownBecomesObservedWhenPassiveHints(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	ip := "10.0.0.55"
	patch := map[string]any{
		"arp": map[string]any{"mac": "11:22:33:44:55:66", "source": "linux_proc"},
	}
	if err := st.MergeHostHints(ctx, ip, patch); err != nil {
		t.Fatalf("MergeHostHints: %v", err)
	}
	now := time.Now().UTC()
	if err := st.UpsertHost(ctx, Host{
		IP: ip, Reachability: "unknown", Label: "", Confidence: "low", LastSeen: now,
	}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	hosts, err := st.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Reachability != "observed" {
		t.Fatalf("expected observed after unknown upsert with hints, got %+v", hosts)
	}
}

func TestStoreUpsertAndListHosts(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Second)
	h := Host{
		IP:           "192.168.1.10",
		Reachability: "reachable",
		OpenPorts:    []string{"443", "80"},
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
	if hosts[0].IP != h.IP || hosts[0].Reachability != h.Reachability || len(hosts[0].OpenPorts) != 2 ||
		hosts[0].OpenPorts[0] != "80" || hosts[0].OpenPorts[1] != "443" {
		t.Fatalf("unexpected host row: %+v", hosts[0])
	}

	// Later scan: unknown clears open ports from Upsert.
	if err := st.UpsertHost(ctx, Host{
		IP: h.IP, Reachability: "unknown", OpenPorts: nil, Label: h.Label, Confidence: "unknown", LastSeen: now,
	}); err != nil {
		t.Fatalf("UpsertHost second: %v", err)
	}
	hosts2, err := st.ListHosts(ctx)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts2) != 1 || len(hosts2[0].OpenPorts) != 0 {
		t.Fatalf("expected open_ports cleared, got %+v", hosts2[0])
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

	id, err := st.InsertScanRun(ctx, "normal", "192.168.1.0/24")
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

func TestListRecentScanRuns(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()
	runs, err := st.ListRecentScanRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListRecentScanRuns: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("expected no runs, got %d", len(runs))
	}
	id1, err := st.InsertScanRun(ctx, "normal", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("InsertScanRun: %v", err)
	}
	id2, err := st.InsertScanRun(ctx, "light", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("InsertScanRun: %v", err)
	}
	runs, err = st.ListRecentScanRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListRecentScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(runs))
	}
	if runs[0].ID != id2 || runs[1].ID != id1 {
		t.Fatalf("expected newest first: got ids %d, %d", runs[0].ID, runs[1].ID)
	}
}

func TestWebEnrichmentSettings(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()
	en, err := st.WebEnrichmentEnabled(ctx)
	if err != nil || en {
		t.Fatalf("default enabled=%v err=%v", en, err)
	}
	p, _ := st.WebEnrichmentProvider(ctx)
	if p != "openai" {
		t.Fatalf("default provider %q", p)
	}
	if err := st.SetWebEnrichment(ctx, WebEnrichmentUpdate{
		Enabled:   true,
		Provider:  "openai",
		OpenAIKey: "sk-test",
	}); err != nil {
		t.Fatal(err)
	}
	en, _ = st.WebEnrichmentEnabled(ctx)
	if !en {
		t.Fatal("expected enabled")
	}
	k, err := st.OpenAIAPIKey(ctx)
	if err != nil || k != "sk-test" {
		t.Fatalf("key %q err %v", k, err)
	}
	if err := st.SetWebEnrichment(ctx, WebEnrichmentUpdate{
		Enabled:        false,
		ClearOpenAIKey: true,
	}); err != nil {
		t.Fatal(err)
	}
	ok, _ := st.OpenAIAPIKeyConfigured(ctx)
	if ok {
		t.Fatal("expected key cleared")
	}
	if err := st.SetWebEnrichment(ctx, WebEnrichmentUpdate{
		Enabled:      true,
		Provider:     "anthropic",
		AnthropicKey: "sk-ant-test",
	}); err != nil {
		t.Fatal(err)
	}
	p, _ = st.WebEnrichmentProvider(ctx)
	if p != "anthropic" {
		t.Fatalf("provider %q", p)
	}
	ak, err := st.AnthropicAPIKey(ctx)
	if err != nil || ak != "sk-ant-test" {
		t.Fatalf("anthropic key %q err %v", ak, err)
	}
}

func TestNmapEnrichmentSettings(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()
	en, err := st.NmapEnrichmentEnabled(ctx)
	if err != nil || en {
		t.Fatalf("default enabled=%v err=%v", en, err)
	}
	if err := st.SetNmapEnrichment(ctx, true); err != nil {
		t.Fatal(err)
	}
	en, err = st.NmapEnrichmentEnabled(ctx)
	if err != nil || !en {
		t.Fatalf("after enable: %v err=%v", en, err)
	}
	if err := st.SetNmapEnrichment(ctx, false); err != nil {
		t.Fatal(err)
	}
	en, _ = st.NmapEnrichmentEnabled(ctx)
	if en {
		t.Fatal("expected disabled")
	}
}

func TestReplaceHostFindingsRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	ip := "192.168.0.44"
	if err := st.UpsertHost(ctx, Host{
		IP: ip, Reachability: "reachable", Label: "x", Confidence: "low",
		LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	f1 := Finding{
		Surface: "upnp/device", VendorGuess: "V", ProductGuess: "P", VersionGuess: "1",
		VersionConfidence: "high", EvidenceKind: "upnp_device_xml", EvidenceDigest: "abc",
		VulnReady: true,
	}
	if err := st.ReplaceHostFindings(ctx, ip, []Finding{f1}); err != nil {
		t.Fatalf("ReplaceHostFindings: %v", err)
	}
	list, err := st.ListFindingsByHost(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 row, got %d", len(list))
	}
	if list[0].Surface != "upnp/device" || !list[0].VulnReady || list[0].ID == 0 {
		t.Fatalf("bad row: %+v", list[0])
	}
	if err := st.ReplaceHostFindings(ctx, ip, nil); err != nil {
		t.Fatal(err)
	}
	list2, err := st.ListFindingsByHost(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(list2) != 0 {
		t.Fatalf("expected cleared, got %d", len(list2))
	}
}

func TestNVDAPIKeyConfigured(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()
	ok, err := st.NVDAPIKeyConfigured(ctx)
	if err != nil {
		t.Fatalf("NVDAPIKeyConfigured: %v", err)
	}
	if ok {
		t.Fatal("expected no key")
	}
	if err := st.CompleteFirstRun(ctx, "192.168.1.0/24", "secret-key"); err != nil {
		t.Fatalf("CompleteFirstRun: %v", err)
	}
	ok, err = st.NVDAPIKeyConfigured(ctx)
	if err != nil || !ok {
		t.Fatalf("expected key configured, ok=%v err=%v", ok, err)
	}
	if err := st.CompleteFirstRun(ctx, "192.168.1.0/24", "   "); err != nil {
		t.Fatalf("CompleteFirstRun clear: %v", err)
	}
	ok, err = st.NVDAPIKeyConfigured(ctx)
	if err != nil || ok {
		t.Fatalf("expected key cleared, ok=%v err=%v", ok, err)
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
	endedAt         time.Time
	cancelRequested int
}, error) {
	type scanRow struct {
		endedAtStr      string
		cancelRequested int
	}
	var r scanRow
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&r.endedAtStr, &r.cancelRequested); err != nil {
		return struct {
			endedAt         time.Time
			cancelRequested int
		}{}, err
	}
	endedAt, _ := time.Parse(time.RFC3339Nano, r.endedAtStr)
	return struct {
		endedAt         time.Time
		cancelRequested int
	}{endedAt: endedAt, cancelRequested: r.cancelRequested}, nil
}
