package discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type Result struct {
	IP           string    `json:"ip"`
	Reachable    bool      `json:"reachable"`
	ObservedAt   time.Time `json:"observed_at"`
	Confidence   string    `json:"confidence"`
	Reachability string    `json:"reachability"`
	// OpenPorts lists every TCP port that accepted a connect (default build), or {"icmp"} for integration ICMP probe.
	OpenPorts []string `json:"open_ports,omitempty"`
}

type Status struct {
	Running         bool   `json:"running"`
	ScanPhase       string `json:"scan_phase"`
	Completed       int    `json:"completed"`
	Total           int    `json:"total"`
	CancelSupported bool   `json:"cancel_supported"`
}

// ScanOptions configures a sweep. Zero value: concurrency 32, TCP profile normal.
type ScanOptions struct {
	Concurrency int
	// TCPProfile is light | normal | thorough (default TCP build); maps to port lists and timeouts.
	// Ignored when built with the integration tag (ICMP probe).
	TCPProfile string
}

type Scanner struct {
	mu        sync.RWMutex
	status    Status
	cancelFn  context.CancelFunc
	lastRunID int64

	probeDebugMu sync.Mutex
	probeDebug   func(string, ...any) // set via SetDebugLog; must not block
}

func NewScanner() *Scanner {
	return &Scanner{
		status: Status{
			Running:         false,
			ScanPhase:       "idle",
			Completed:       0,
			Total:           0,
			CancelSupported: true,
		},
	}
}

func (s *Scanner) Start(ctx context.Context, cidr string, opts ScanOptions, onResult func(Result) error) (int64, error) {
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return 0, errors.New("scan already running")
	}
	ips, err := hostsFromCIDR(cidr)
	if err != nil {
		s.mu.Unlock()
		return 0, err
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 32
	}
	tcpProfile := NormalizeTCPProfile(opts.TCPProfile)
	scanCtx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	s.lastRunID++
	runID := s.lastRunID
	s.status = Status{
		Running:         true,
		ScanPhase:       "probe",
		Completed:       0,
		Total:           len(ips),
		CancelSupported: true,
	}
	s.mu.Unlock()

	go s.scan(scanCtx, ips, concurrency, tcpProfile, onResult, runID)
	return runID, nil
}

// SetDebugLog registers a logger for per-host probe lines when non-nil. Safe to call before Start.
func (s *Scanner) SetDebugLog(f func(string, ...any)) {
	s.probeDebugMu.Lock()
	s.probeDebug = f
	s.probeDebugMu.Unlock()
}

func (s *Scanner) probeLogf(format string, args ...any) {
	s.probeDebugMu.Lock()
	f := s.probeDebug
	s.probeDebugMu.Unlock()
	if f != nil {
		f(format, args...)
	}
}

func (s *Scanner) scan(ctx context.Context, ips []string, concurrency int, tcpProfile string, onResult func(Result) error, runID int64) {
	if concurrency <= 0 {
		concurrency = 32
	}
	s.probeLogf("scan run_id=%d hosts=%d concurrency=%d tcp_profile=%s first_ip=%s last_ip=%s",
		runID, len(ips), concurrency, tcpProfile, firstIP(ips), lastIP(ips))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			s.finish("cancelled")
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			reachable, openPorts := probeReachable(ctx, ip, tcpProfile)
			s.probeLogf("probe run_id=%d ip=%s tcp_profile=%s reachable=%t open_ports=%v reachability=%s",
				runID, ip, tcpProfile, reachable, openPorts, map[bool]string{true: "reachable", false: "unknown"}[reachable])
			now := time.Now().UTC()
			_ = onResult(Result{
				IP:           ip,
				Reachable:    reachable,
				ObservedAt:   now,
				Confidence:   "unknown",
				Reachability: map[bool]string{true: "reachable", false: "unknown"}[reachable],
				OpenPorts:    openPorts,
			})
			s.incrementCompleted()
		}(ip)

		// Politeness jitter between dispatches.
		time.Sleep(20*time.Millisecond + time.Duration(time.Now().UnixNano()%25)*time.Millisecond)
	}

	wg.Wait()
	s.probeLogf("scan run_id=%d probe_loop_finished", runID)
	select {
	case <-ctx.Done():
		s.finish("cancelled")
	default:
		s.finish("done")
	}
}

func (s *Scanner) Cancel() bool {
	s.mu.RLock()
	cancel := s.cancelFn
	running := s.status.Running
	s.mu.RUnlock()
	if running && cancel != nil {
		cancel()
		return true
	}
	return false
}

func (s *Scanner) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Scanner) incrementCompleted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Completed++
}

func (s *Scanner) finish(phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Running = false
	s.status.ScanPhase = phase
}

func firstIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func lastIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	return ips[len(ips)-1]
}

func hostsFromCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip = ip.Mask(ipNet.Mask)
	out := make([]string, 0, 256)
	for current := append(net.IP(nil), ip...); ipNet.Contains(current); incIP(current) {
		out = append(out, current.String())
	}
	if len(out) <= 2 {
		return out, nil
	}
	// Drop network and broadcast for typical IPv4 subnet scans.
	return out[1 : len(out)-1], nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
