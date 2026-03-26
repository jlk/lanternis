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
}

type Status struct {
	Running         bool   `json:"running"`
	ScanPhase       string `json:"scan_phase"`
	Completed       int    `json:"completed"`
	Total           int    `json:"total"`
	CancelSupported bool   `json:"cancel_supported"`
}

type Scanner struct {
	mu        sync.RWMutex
	status    Status
	cancelFn  context.CancelFunc
	lastRunID int64
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

func (s *Scanner) Start(ctx context.Context, cidr string, concurrency int, onResult func(Result) error) (int64, error) {
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
	scanCtx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	s.lastRunID++
	runID := s.lastRunID
	s.status = Status{
		Running:         true,
		ScanPhase:       "icmp",
		Completed:       0,
		Total:           len(ips),
		CancelSupported: true,
	}
	s.mu.Unlock()

	go s.scan(scanCtx, ips, concurrency, onResult)
	return runID, nil
}

func (s *Scanner) scan(ctx context.Context, ips []string, concurrency int, onResult func(Result) error) {
	if concurrency <= 0 {
		concurrency = 32
	}
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

			reachable := pingHost(ctx, ip)
			now := time.Now().UTC()
			_ = onResult(Result{
				IP:           ip,
				Reachable:    reachable,
				ObservedAt:   now,
				Confidence:   "unknown",
				Reachability: map[bool]string{true: "reachable", false: "unknown"}[reachable],
			})
			s.incrementCompleted()
		}(ip)

		// Politeness jitter between dispatches.
		time.Sleep(20*time.Millisecond + time.Duration(time.Now().UnixNano()%25)*time.Millisecond)
	}

	wg.Wait()
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
