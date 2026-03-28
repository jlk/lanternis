package passive

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

// SSDPEntry aggregates UPnP/SSDP discovery responses from one IPv4 host within a collect window.
type SSDPEntry struct {
	IP       string   `json:"ip"`
	STTypes  []string `json:"st_types,omitempty"`
	USNs     []string `json:"usns,omitempty"`
	Server   string   `json:"server,omitempty"`
	Location string   `json:"location,omitempty"`
}

const ssdpMulticast = "239.255.255.250:1900"

const msearchPayload = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"ST: ssdp:all\r\n" +
	"MX: 2\r\n\r\n"

// CollectSSDP sends one M-SEARCH (ssdp:all) and reads UDP responses for up to ~3s (bounded even if parent ctx is long).
// cidr selects a local IPv4 on that subnet to bind the socket; if none matches, binds 0.0.0.0.
func CollectSSDP(ctx context.Context, cidr string) ([]SSDPEntry, error) {
	sub, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	deadline, _ := sub.Deadline()

	_, localIP, err := findLANMatch(cidr)
	if err != nil {
		return nil, err
	}
	var conn net.PacketConn
	if localIP != nil {
		conn, err = net.ListenPacket("udp4", net.JoinHostPort(localIP.String(), "0"))
	} else {
		conn, err = net.ListenPacket("udp4", "0.0.0.0:0")
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", ssdpMulticast)
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo([]byte(msearchPayload), dst); err != nil {
		return nil, err
	}

	agg := make(map[string]*ssdpAggHost)
	buf := make([]byte, 8192)

	for {
		if sub.Err() != nil {
			return finalizeSSDP(agg), nil
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		if rem > 750*time.Millisecond {
			rem = 750 * time.Millisecond
		}
		_ = conn.SetReadDeadline(time.Now().Add(rem))
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return finalizeSSDP(agg), err
		}
		udp, ok := raddr.(*net.UDPAddr)
		if !ok || udp.IP == nil {
			continue
		}
		ip4 := udp.IP.To4()
		if ip4 == nil {
			continue
		}
		ip := ip4.String()
		h := parseSSDPResponse(string(buf[:n]))
		if h == nil {
			continue
		}
		a := agg[ip]
		if a == nil {
			a = &ssdpAggHost{
				stSet:  make(map[string]struct{}),
				usnSet: make(map[string]struct{}),
			}
			agg[ip] = a
		}
		if h.st != "" {
			a.stSet[h.st] = struct{}{}
		}
		if h.usn != "" {
			a.usnSet[h.usn] = struct{}{}
		}
		if h.server != "" {
			a.server = h.server
		}
		if h.location != "" {
			a.location = h.location
		}
	}

	return finalizeSSDP(agg), nil
}

type ssdpAggHost struct {
	stSet    map[string]struct{}
	usnSet   map[string]struct{}
	server   string
	location string
}

type ssdpParsed struct {
	st, usn, server, location string
}

func finalizeSSDP(agg map[string]*ssdpAggHost) []SSDPEntry {
	if len(agg) == 0 {
		return nil
	}
	ips := make([]string, 0, len(agg))
	for ip := range agg {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := make([]SSDPEntry, 0, len(ips))
	for _, ip := range ips {
		a := agg[ip]
		stList := make([]string, 0, len(a.stSet))
		for st := range a.stSet {
			stList = append(stList, st)
		}
		sort.Strings(stList)
		usnList := make([]string, 0, len(a.usnSet))
		for u := range a.usnSet {
			usnList = append(usnList, u)
		}
		sort.Strings(usnList)
		out = append(out, SSDPEntry{
			IP:       ip,
			STTypes:  stList,
			USNs:     usnList,
			Server:   a.server,
			Location: a.location,
		})
	}
	return out
}

func parseSSDPResponse(body string) *ssdpParsed {
	first := strings.SplitN(body, "\n", 2)[0]
	first = strings.TrimSpace(first)
	if !strings.HasPrefix(strings.ToUpper(first), "HTTP/") {
		return nil
	}
	lines := strings.Split(body, "\n")
	hdr := make(map[string]string)
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		hdr[strings.ToUpper(k)] = v
	}
	st := hdr["ST"]
	if st == "" {
		return nil
	}
	return &ssdpParsed{
		st:       st,
		usn:      hdr["USN"],
		server:   hdr["SERVER"],
		location: hdr["LOCATION"],
	}
}
