package fingerprint

import (
	"strings"
	"testing"
)

func TestInferOSFromSSHUbuntu(t *testing.T) {
	t.Parallel()
	ev := inferOSFromSSH(`SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`)
	if ev == nil || ev.family != OSFamilyLinux || ev.score < 60 {
		t.Fatalf("got %+v", ev)
	}
}

func TestInferOSFromSSHOpenSSHOnly(t *testing.T) {
	t.Parallel()
	ev := inferOSFromSSH(`SSH-2.0-OpenSSH_8.4`)
	if ev == nil || ev.family != OSFamilyUnknown {
		t.Fatalf("got %+v", ev)
	}
}

func TestInferOSFromHTTPServerIIS(t *testing.T) {
	t.Parallel()
	ev := inferOSFromHTTPServer("Microsoft-IIS/10.0")
	if ev == nil || ev.family != OSFamilyWindows {
		t.Fatalf("got %+v", ev)
	}
}

func TestInferOSFromSSDP(t *testing.T) {
	t.Parallel()
	ev := inferOSFromSSDPServer("Linux, UPnP/1.0, Private SDK")
	if ev == nil || ev.family != OSFamilyLinux {
		t.Fatalf("got %+v", ev)
	}
}

func TestInferOSFromSMBNative(t *testing.T) {
	t.Parallel()
	ev := inferOSFromSMBNative("Windows 10 Enterprise 17763", "Samba 4.15.13")
	if ev == nil || ev.family != OSFamilyWindows {
		t.Fatalf("got %+v", ev)
	}
}

func TestApplyOSInferenceMerge(t *testing.T) {
	t.Parallel()
	rec := &Record{SchemaVersion: 1}
	pctx := ProbeContext{
		SSHBanner:     `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`,
		HTTPServer80:  "nginx/1.22.1",
		HTTPServer443: "Microsoft-IIS/10.0",
	}
	hints := map[string]any{
		"ssdp": map[string]any{"server": "Linux, UPnP/1.0"},
	}
	ApplyOSInference(rec, hints, pctx)
	// IIS / Windows should beat Debian SSH on score? Debian 72, IIS 62, SSDP linux 40
	if rec.OSFamily != OSFamilyLinux || !strings.Contains(rec.OSDetail, "Debian") {
		t.Fatalf("want Debian SSH to win, got family=%q detail=%q", rec.OSFamily, rec.OSDetail)
	}
}
