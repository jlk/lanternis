// Package nmapenrich runs optional per-host Nmap scans to add version and NSE script evidence.
// Requires the `nmap` binary on PATH when enrichment is enabled.
package nmapenrich

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jlk/lanternis/internal/fingerprint"
)

// LookPath returns the path to nmap if it is on PATH.
func LookPath() (string, bool) {
	p, err := exec.LookPath("nmap")
	if err != nil || strings.TrimSpace(p) == "" {
		return "", false
	}
	return p, true
}

// AllowedNSEScripts is a conservative allowlist (safe category scripts, IoT-relevant).
const AllowedNSEScripts = "upnp-info,http-title,http-headers,ssl-cert,ssh-hostkey,ssh2-enum-algos"

// Options tune per-host scan bounds.
type Options struct {
	HostTimeout   time.Duration
	ScriptTimeout time.Duration
}

// DefaultOptions returns bounded defaults suitable for LAN inventory.
func DefaultOptions() Options {
	return Options{
		HostTimeout:   60 * time.Second,
		ScriptTimeout: 30 * time.Second,
	}
}

var runNmap = defaultRunNmap

func defaultRunNmap(ctx context.Context, name string, arg ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, arg...)
	return cmd.Output()
}

// Enrich runs nmap against hostIP for selected ports and appends nmap-backed signals to rec.
func Enrich(ctx context.Context, rec *fingerprint.Record, hostIP string, openPorts []string, hints map[string]any, nmapPath string, opts Options) error {
	if rec == nil || strings.TrimSpace(hostIP) == "" || strings.TrimSpace(nmapPath) == "" {
		return nil
	}
	tcp, udp1900 := BuildPortSpec(openPorts, hints)
	if len(tcp) == 0 && !udp1900 {
		return nil
	}

	var portSpec string
	switch {
	case udp1900 && len(tcp) > 0:
		portSpec = "U:1900,T:" + strings.Join(tcp, ",")
	case udp1900:
		portSpec = "U:1900"
	default:
		portSpec = strings.Join(tcp, ",")
	}

	args := []string{
		"-Pn", "-n",
		"--host-timeout", formatDur(opts.HostTimeout),
		"--script-timeout", formatDur(opts.ScriptTimeout),
		"-oX", "-",
	}
	if udp1900 && len(tcp) > 0 {
		args = append(args, "-sT", "-sU", "-p", portSpec)
	} else if udp1900 {
		args = append(args, "-sU", "-p", portSpec)
	} else {
		args = append(args, "-sT", "-p", portSpec)
	}
	args = append(args,
		"-sV", "--version-light",
		"--script", AllowedNSEScripts,
		hostIP,
	)
	out, err := runNmap(ctx, nmapPath, args...)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return fmt.Errorf("nmap: %w: %s", err, truncateRunes(string(ee.Stderr), 200))
		}
		return fmt.Errorf("nmap: %w", err)
	}
	ports, err := ParseNmapXML(bytes.NewReader(out))
	if err != nil {
		return err
	}
	AppendParsedPortsToRecord(rec, ports)
	return nil
}

func formatDur(d time.Duration) string {
	if d <= 0 {
		d = 60 * time.Second
	}
	return d.String()
}
