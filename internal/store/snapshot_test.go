package store

import (
	"context"
	"testing"
	"time"
)

func TestReplaceScanSnapshotAndDiff(t *testing.T) {
	ctx := context.Background()
	st, cleanup := mustTestStore(t, ctx)
	defer cleanup()

	id1, err := st.InsertScanRun(ctx, "normal", "192.168.1.0/24")
	if err != nil {
		t.Fatalf("InsertScanRun: %v", err)
	}
	now := time.Now().UTC()
	hosts := []Host{
		{IP: "192.168.1.1", Reachability: "reachable", OpenPorts: []string{"80"}, Label: "", Confidence: "unknown", LastSeen: now},
		{IP: "192.168.1.2", Reachability: "unknown", OpenPorts: nil, Label: "", Confidence: "unknown", LastSeen: now},
	}
	if err := st.ReplaceScanSnapshot(ctx, id1, "192.168.1.0/24", hosts); err != nil {
		t.Fatalf("ReplaceScanSnapshot 1: %v", err)
	}
	if err := st.MarkScanEnded(ctx, id1, false); err != nil {
		t.Fatalf("MarkScanEnded: %v", err)
	}

	id2, err := st.InsertScanRun(ctx, "normal", "192.168.1.0/24")
	if err != nil {
		t.Fatalf("InsertScanRun 2: %v", err)
	}
	hosts2 := []Host{
		{IP: "192.168.1.1", Reachability: "reachable", OpenPorts: []string{"80", "443"}, Label: "", Confidence: "unknown", LastSeen: now},
		{IP: "192.168.1.3", Reachability: "reachable", OpenPorts: []string{"22"}, Label: "", Confidence: "low", LastSeen: now},
	}
	if err := st.ReplaceScanSnapshot(ctx, id2, "192.168.1.0/24", hosts2); err != nil {
		t.Fatalf("ReplaceScanSnapshot 2: %v", err)
	}
	if err := st.MarkScanEnded(ctx, id2, false); err != nil {
		t.Fatalf("MarkScanEnded 2: %v", err)
	}

	diff, err := st.BuildScanDiff(ctx)
	if err != nil {
		t.Fatalf("BuildScanDiff: %v", err)
	}
	if diff.CurrentScanID != id2 || diff.PreviousScanID != id1 {
		t.Fatalf("unexpected ids: %+v", diff)
	}
	if len(diff.HostsAdded) != 1 || diff.HostsAdded[0].IP != "192.168.1.3" {
		t.Fatalf("hosts_added: %+v", diff.HostsAdded)
	}
	if len(diff.HostsRemoved) != 1 || diff.HostsRemoved[0].IP != "192.168.1.2" {
		t.Fatalf("hosts_removed: %+v", diff.HostsRemoved)
	}
	if len(diff.NewOpenPorts) != 1 || diff.NewOpenPorts[0].IP != "192.168.1.1" {
		t.Fatalf("new_open_ports: %+v", diff.NewOpenPorts)
	}
	if len(diff.NewOpenPorts[0].Ports) != 1 || diff.NewOpenPorts[0].Ports[0] != "443" {
		t.Fatalf("ports: %+v", diff.NewOpenPorts[0].Ports)
	}
}

func TestIPInCIDRStore(t *testing.T) {
	if !ipInCIDR("192.168.1.5", "192.168.1.0/24") {
		t.Fatal("expected in")
	}
	if ipInCIDR("10.0.0.1", "192.168.1.0/24") {
		t.Fatal("expected out")
	}
}
