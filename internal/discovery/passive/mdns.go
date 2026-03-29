package passive

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultMDNSListen = 3500 * time.Millisecond

// MDNSService represents a service announcement tied to one address during a collect window.
type MDNSService struct {
	Type     string   `json:"type"`
	Instance string   `json:"instance,omitempty"`
	Port     int      `json:"port,omitempty"`
	TXT      []string `json:"txt,omitempty"`
}

// MDNSEntry aggregates mDNS hostnames and services seen for one IPv4 address during a collect window.
type MDNSEntry struct {
	IP       string        `json:"ip"`
	Names    []string      `json:"names,omitempty"`
	Services []MDNSService `json:"services,omitempty"`
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

	agg := newMDNSAgg()
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

type mdnsAgg struct {
	namesByIP    map[string]map[string]struct{}
	hostToIP     map[string]string
	instanceToTy map[string]map[string]struct{} // instance -> type
	instanceSRV  map[string]mdnsSRV
	instanceTXT  map[string][]string
}

type mdnsSRV struct {
	Target string
	Port   int
}

func newMDNSAgg() *mdnsAgg {
	return &mdnsAgg{
		namesByIP:    make(map[string]map[string]struct{}),
		hostToIP:     make(map[string]string),
		instanceToTy: make(map[string]map[string]struct{}),
		instanceSRV:  make(map[string]mdnsSRV),
		instanceTXT:  make(map[string][]string),
	}
}

func addDNSMsg(msg *dns.Msg, agg *mdnsAgg) {
	rrs := append(append(msg.Answer, msg.Extra...), msg.Ns...)
	for _, rr := range rrs {
		switch t := rr.(type) {
		case *dns.A:
			if t.A == nil {
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
			agg.hostToIP[nm] = ip4.String()
			addName(agg, ip4.String(), nm)
		case *dns.PTR:
			ty := normalizeMDNSName(t.Hdr.Name)
			inst := normalizeMDNSName(t.Ptr)
			if ty == "" || inst == "" {
				continue
			}
			if agg.instanceToTy[inst] == nil {
				agg.instanceToTy[inst] = make(map[string]struct{})
			}
			agg.instanceToTy[inst][ty] = struct{}{}
		case *dns.SRV:
			inst := normalizeMDNSName(t.Hdr.Name)
			target := normalizeMDNSName(t.Target)
			if inst == "" || target == "" || t.Port == 0 {
				continue
			}
			agg.instanceSRV[inst] = mdnsSRV{Target: target, Port: int(t.Port)}
		case *dns.TXT:
			inst := normalizeMDNSName(t.Hdr.Name)
			if inst == "" || len(t.Txt) == 0 {
				continue
			}
			// Store at most a small number of keys to avoid blowing up raw_hints.
			if len(t.Txt) > 24 {
				agg.instanceTXT[inst] = append([]string{}, t.Txt[:24]...)
			} else {
				agg.instanceTXT[inst] = append([]string{}, t.Txt...)
			}
		}
	}
}

func addName(agg *mdnsAgg, ip, name string) {
	if agg.namesByIP[ip] == nil {
		agg.namesByIP[ip] = make(map[string]struct{})
	}
	agg.namesByIP[ip][name] = struct{}{}
}

func normalizeMDNSName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

func finalizeMDNS(agg *mdnsAgg) []MDNSEntry {
	if agg == nil || (len(agg.namesByIP) == 0 && len(agg.instanceSRV) == 0) {
		return nil
	}
	servicesByIP := make(map[string]map[string]MDNSService)
	for inst, srv := range agg.instanceSRV {
		ip := agg.hostToIP[srv.Target]
		if ip == "" {
			continue
		}
		types := agg.instanceToTy[inst]
		if len(types) == 0 {
			continue
		}
		for ty := range types {
			svc := MDNSService{
				Type:     ty,
				Instance: inst,
				Port:     srv.Port,
				TXT:      agg.instanceTXT[inst],
			}
			key := ty + "|" + inst + "|" + strconv.Itoa(srv.Port)
			if servicesByIP[ip] == nil {
				servicesByIP[ip] = make(map[string]MDNSService)
			}
			servicesByIP[ip][key] = svc
		}
	}

	allIPs := make(map[string]struct{})
	for ip := range agg.namesByIP {
		allIPs[ip] = struct{}{}
	}
	for ip := range servicesByIP {
		allIPs[ip] = struct{}{}
	}
	ips := make([]string, 0, len(allIPs))
	for ip := range allIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := make([]MDNSEntry, 0, len(ips))
	for _, ip := range ips {
		set := agg.namesByIP[ip]
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		var services []MDNSService
		if sm := servicesByIP[ip]; len(sm) > 0 {
			services = make([]MDNSService, 0, len(sm))
			for _, s := range sm {
				services = append(services, s)
			}
			sort.Slice(services, func(i, j int) bool {
				if services[i].Type != services[j].Type {
					return services[i].Type < services[j].Type
				}
				if services[i].Port != services[j].Port {
					return services[i].Port < services[j].Port
				}
				return services[i].Instance < services[j].Instance
			})
		}
		out = append(out, MDNSEntry{IP: ip, Names: names, Services: services})
	}
	return out
}
