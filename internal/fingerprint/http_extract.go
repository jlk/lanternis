package fingerprint

import (
	"encoding/json"
	"regexp"
	"strings"
)

// HTTPExtractPayload is stored in Signal.Value for Source "http_extract" (JSON).
type HTTPExtractPayload struct {
	Kind     string `json:"kind"`     // server | body_regex | body_json
	Product  string `json:"product"`  // e.g. nginx, Apache
	Version  string `json:"version"`  // best-effort parsed token
	Conf     string `json:"conf"`     // high | medium | low
	Evidence string `json:"evidence"` // truncated snippet (not secrets)
	Path     string `json:"path,omitempty"`
}

var (
	reServerProduct = regexp.MustCompile(`(?i)(nginx|Apache(?:\s|$)|Microsoft-IIS|lighttpd|caddy|uhttpd|openresty)[/\s]+([0-9][0-9a-z._-]*)`)
	reGenericServer = regexp.MustCompile(`(?i)^([a-zA-Z][a-zA-Z0-9._-]{0,32})/([0-9][0-9a-z._-]*)`)
	reJSONVersion   = regexp.MustCompile(`"(?:version|firmware|Firmware|build|Build)"\s*:\s*"([^"]{1,128})"`)
	reKVVersion     = regexp.MustCompile(`(?i)(?:firmware|Firmware|version|Version|build|Build)\s*[:=]\s*([0-9a-z._\-]{2,48})`)
)

// ExtractHTTPVersionHints pulls version-like tokens from an HTTP index body and Server header.
func ExtractHTTPVersionHints(body []byte, serverHeader string) []HTTPExtractPayload {
	var out []HTTPExtractPayload
	seen := map[string]struct{}{}
	add := func(kind, product, version, conf, evidence string) {
		version = strings.TrimSpace(version)
		if version == "" && product == "" {
			return
		}
		key := kind + "|" + strings.ToLower(product) + "|" + strings.ToLower(version)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		ev := evidence
		if len(ev) > 120 {
			ev = ev[:117] + "…"
		}
		out = append(out, HTTPExtractPayload{
			Kind: kind, Product: strings.TrimSpace(product), Version: version,
			Conf: conf, Evidence: ev,
		})
	}

	sh := strings.TrimSpace(serverHeader)
	if sh != "" {
		if m := reServerProduct.FindStringSubmatch(sh); len(m) >= 3 {
			add("server", m[1], m[2], "high", sh)
		} else if m := reGenericServer.FindStringSubmatch(sh); len(m) >= 3 {
			add("server", m[1], m[2], "medium", sh)
		}
	}

	s := string(body)
	for _, m := range reJSONVersion.FindAllStringSubmatch(s, 4) {
		if len(m) >= 2 {
			add("body_json", "", strings.TrimSpace(m[1]), "medium", m[0])
		}
	}
	if m := reKVVersion.FindStringSubmatch(s); len(m) >= 2 {
		add("body_regex", "", strings.TrimSpace(m[1]), "low", m[0])
	}
	return out
}

// MarshalHTTPExtractPayload JSON-encodes one payload for a Signal.Value.
func MarshalHTTPExtractPayload(p HTTPExtractPayload) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseHTTPExtractPayload decodes Signal.Value for Source "http_extract".
func ParseHTTPExtractPayload(s string) (HTTPExtractPayload, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s[0] != '{' {
		return HTTPExtractPayload{}, false
	}
	var p HTTPExtractPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return HTTPExtractPayload{}, false
	}
	return p, p.Version != "" || p.Product != ""
}
