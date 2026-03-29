package fingerprint

import (
	"strings"
	"testing"
)

func TestExtractHTTPVersionHintsServer(t *testing.T) {
	h := ExtractHTTPVersionHints(nil, "nginx/1.24.0")
	if len(h) != 1 || h[0].Product != "nginx" || h[0].Version != "1.24.0" || h[0].Conf != "high" {
		t.Fatalf("nginx: %+v", h)
	}
	h2 := ExtractHTTPVersionHints(nil, "Apache/2.4.52 (Debian)")
	if len(h2) != 1 || h2[0].Product != "Apache" || h2[0].Version != "2.4.52" {
		t.Fatalf("apache: %+v", h2)
	}
}

func TestExtractHTTPVersionHintsBodyJSON(t *testing.T) {
	body := []byte(`{"name":"cam","Firmware":"3.1.2","ok":true}`)
	h := ExtractHTTPVersionHints(body, "")
	if len(h) < 1 {
		t.Fatalf("expected json hint, got %+v", h)
	}
	found := false
	for _, x := range h {
		if x.Kind == "body_json" && strings.Contains(x.Version, "3.1.2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected firmware version in %+v", h)
	}
}
