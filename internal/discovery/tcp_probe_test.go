//go:build !integration

package discovery

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestNormalizeTCPProfile(t *testing.T) {
	if got := NormalizeTCPProfile(""); got != TCPProfileNormal {
		t.Fatalf("empty: got %q", got)
	}
	if got := NormalizeTCPProfile("lite"); got != TCPProfileLight {
		t.Fatalf("lite: got %q", got)
	}
	if got := NormalizeTCPProfile("THOROUGH"); got != TCPProfileThorough {
		t.Fatalf("thorough: got %q", got)
	}
	if got := NormalizeTCPProfile("weird"); got != TCPProfileNormal {
		t.Fatalf("unknown: got %q", got)
	}
}

func TestPortsForTCPProfileTiers(t *testing.T) {
	light := PortsForTCPProfile(TCPProfileLight)
	normal := PortsForTCPProfile(TCPProfileNormal)
	thorough := PortsForTCPProfile(TCPProfileThorough)
	if len(light) >= len(normal) || len(normal) >= len(thorough) {
		t.Fatalf("expected light < normal < thorough counts, got %d %d %d", len(light), len(normal), len(thorough))
	}
	if len(dedupeStringsStable(thorough)) != len(thorough) {
		t.Fatal("thorough list has duplicates")
	}
}

func TestTCPReachableWithPorts_LocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	portStr := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ok, got := tcpReachableWithPorts(context.Background(), "127.0.0.1", []string{portStr}, 400*time.Millisecond)
	if !ok || len(got) != 1 || got[0] != portStr {
		t.Fatalf("expected open port %s, ok=%v got=%v", portStr, ok, got)
	}
}

func TestTCPReachableWithPorts_MultipleListeners(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	p1 := strconv.Itoa(ln1.Addr().(*net.TCPAddr).Port)
	p2 := strconv.Itoa(ln2.Addr().(*net.TCPAddr).Port)
	acceptLoop := func(ln net.Listener) {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	acceptLoop(ln1)
	acceptLoop(ln2)

	ok, got := tcpReachableWithPorts(context.Background(), "127.0.0.1", []string{p2, p1, "1"}, 600*time.Millisecond)
	if !ok || len(got) != 2 {
		t.Fatalf("expected 2 open ports, ok=%v got=%v", ok, got)
	}
	if got[0] > got[1] {
		t.Fatalf("expected numeric sort, got %v", got)
	}
}

func TestTCPReachableWithPorts_AllClosed(t *testing.T) {
	ok, got := tcpReachableWithPorts(context.Background(), "127.0.0.1", []string{"1"}, 200*time.Millisecond)
	if ok || len(got) != 0 {
		t.Fatalf("expected closed, ok=%v ports=%v", ok, got)
	}
}
