package passive

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultMDNSListen = 3500 * time.Millisecond

// MDNSEntry aggregates mDNS hostnames seen for one IPv4 address during a collect window.
type MDNSEntry struct {
	IP    string   `json:"ip"`
	Names []string `json:"names,omitempty"`
}

// CollectMDNS listens for mDNS traffic on 224.0.0.251:5353 until listenMax (or default ~3.5s if listenMax <= 0).
// cidr selects the local interface (IPv4 in that net) for multicast; if none matches, uses the OS default.
func CollectMDNS(ctx context.Context, cidr string, listenMax time.Duration) ([]MDNSEntry, error) {
	if listenMax <= 0 {
		listenMax = defaultMDNSListen
	}
	sub, cancel := context.WithTimeout(ctx, listenMax)
	defer cancel()
	deadline, _ := sub.Deadline()

	ifi, err := interfaceForCIDR(cidr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenMulticastUDP("udp4", ifi, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Avoid blocking forever if the interface does not deliver multicast.
	_ = conn.SetReadBuffer(1024 * 1024)

	agg := make(map[string]map[string]struct{})
	buf := make([]byte, 65535)

	for {
		if sub.Err() != nil {
			return finalizeMDNS(agg), nil
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		if rem > 500*time.Millisecond {
			rem = 500 * time.Millisecond
		}
		_ = conn.SetReadDeadline(time.Now().Add(rem))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return finalizeMDNS(agg), err
		}
		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		addDNSMsg(&msg, agg)
	}

	return finalizeMDNS(agg), nil
}

func addDNSMsg(msg *dns.Msg, agg map[string]map[string]struct{}) {
	rrs := append(append(msg.Answer, msg.Extra...), msg.Ns...)
	for _, rr := range rrs {
		t, ok := rr.(*dns.A)
		if !ok || t.A == nil {
			continue
		}
		ip4 := t.A.To4()
		if ip4 == nil {
			continue
		}
		nm := normalizeMDNSName(t.Hdr.Name)
		if nm == "" {
			continue
		}
		addName(agg, ip4.String(), nm)
	}
}

func addName(agg map[string]map[string]struct{}, ip, name string) {
	if agg[ip] == nil {
		agg[ip] = make(map[string]struct{})
	}
	agg[ip][name] = struct{}{}
}

func normalizeMDNSName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

func finalizeMDNS(agg map[string]map[string]struct{}) []MDNSEntry {
	if len(agg) == 0 {
		return nil
	}
	ips := make([]string, 0, len(agg))
	for ip := range agg {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := make([]MDNSEntry, 0, len(ips))
	for _, ip := range ips {
		set := agg[ip]
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, MDNSEntry{IP: ip, Names: names})
	}
	return out
}
