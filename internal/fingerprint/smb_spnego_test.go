package fingerprint

import "testing"

func TestBuildSMBSessionSecurityBlob(t *testing.T) {
	t.Parallel()
	b, err := buildSMBSessionSecurityBlob()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 20 || b[0] != 0x60 {
		t.Fatalf("expected GSS-API wrapped SPNEGO (0x60…), got % x", b[:min(8, len(b))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
