package passive

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ARPEntry is one row from the OS ARP cache (IPv4).
type ARPEntry struct {
	IP     string
	MAC    string
	Source string
}

// IPInCIDR reports whether ipStr is contained in cidr (IPv4).
func IPInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

// CollectARP returns IPv4 ARP entries when supported (Linux, macOS). Other OS: empty, no error.
func CollectARP(ctx context.Context) ([]ARPEntry, error) {
	switch runtime.GOOS {
	case "linux":
		return collectARPLinux(ctx)
	case "darwin":
		return collectARPDarwin(ctx)
	default:
		return nil, nil
	}
}

func collectARPLinux(ctx context.Context) ([]ARPEntry, error) {
	_ = ctx
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	return parseLinuxProcNetARP(string(data)), nil
}

func parseLinuxProcNetARP(data string) []ARPEntry {
	var out []ARPEntry
	sc := bufio.NewScanner(strings.NewReader(data))
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		if !strings.Contains(mac, ":") {
			continue
		}
		if mac == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, ARPEntry{IP: ip, MAC: strings.ToLower(mac), Source: "linux_proc"})
	}
	return out
}

func collectARPDarwin(ctx context.Context) ([]ARPEntry, error) {
	cmd := exec.CommandContext(ctx, "arp", "-an")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseDarwinARPAn(string(out)), nil
}

var darwinARP = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)\s+`)

func parseDarwinARPAn(data string) []ARPEntry {
	var out []ARPEntry
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(strings.ToLower(line), "incomplete") {
			continue
		}
		m := darwinARP.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		out = append(out, ARPEntry{IP: m[1], MAC: strings.ToLower(m[2]), Source: "darwin_arp"})
	}
	return out
}
