package discovery

import (
	"context"
	"testing"
	"time"
)

func TestHostsFromCIDR_DropsNetworkAndBroadcast(t *testing.T) {
	hosts, err := hostsFromCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("hostsFromCIDR: %v", err)
	}
	// /30 has 4 addresses; we keep only the 2 usable host IPs.
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d (%v)", len(hosts), hosts)
	}
	if hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
}

func TestHostsFromCIDR_KeepTwoIPsForSlash31(t *testing.T) {
	hosts, err := hostsFromCIDR("127.0.0.0/31")
	if err != nil {
		t.Fatalf("hostsFromCIDR: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d (%v)", len(hosts), hosts)
	}
}

func TestScannerSecondStartReturnsConflict(t *testing.T) {
	s := NewScanner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use /32 so the scan finishes quickly (connection refused should be immediate).
	_, err := s.Start(ctx, "127.0.0.1/32", ScanOptions{Concurrency: 1}, func(Result) error { return nil })
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}

	_, err = s.Start(ctx, "127.0.0.1/32", ScanOptions{Concurrency: 1}, func(Result) error { return nil })
	if err == nil || err.Error() != "scan already running" {
		t.Fatalf("expected conflict error, got: %v", err)
	}

	// Ensure cancellation path doesn't deadlock the coordinator.
	_ = s.Cancel()
	time.Sleep(50 * time.Millisecond)
}
