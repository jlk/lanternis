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
	if ev == nil || ev.family != OSFamilyUnknown || ev.tier != tierWeak {
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
		SSHBanner:    `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`,
		HTTPServer80: "nginx/1.22.1",
	}
	hints := map[string]any{
		"ssdp": map[string]any{"server": "Linux, UPnP/1.0"},
	}
	ApplyOSInference(rec, hints, pctx)
	// Debian SSH (strong) should win over weak nginx/SSDP text.
	if rec.OSFamily != OSFamilyLinux || !strings.Contains(rec.OSDetail, "Debian") {
		t.Fatalf("want Debian SSH to win, got family=%q detail=%q", rec.OSFamily, rec.OSDetail)
	}
	if rec.OSConflict {
		t.Fatal("unexpected OS conflict")
	}
}

func TestMergeOSConflict(t *testing.T) {
	t.Parallel()
	rec := &Record{SchemaVersion: 1}
	pctx := ProbeContext{
		SSHBanner:     `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`,
		HTTPServer443: "Microsoft-IIS/10.0",
	}
	ApplyOSInference(rec, map[string]any{}, pctx)
	if !rec.OSConflict || rec.OSFamily != OSFamilyUnknown {
		t.Fatalf("want conflict + unknown family, got conflict=%v family=%q detail=%q", rec.OSConflict, rec.OSFamily, rec.OSDetail)
	}
}
