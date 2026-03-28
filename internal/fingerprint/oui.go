package fingerprint

import (
	_ "embed"
	"strings"
)

//go:embed oui_embedded.txt
var ouiRaw string

var ouiMap map[string]string

func init() {
	ouiMap = make(map[string]string)
	for _, line := range strings.Split(ouiRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		vendor := strings.TrimSpace(parts[1])
		if len(prefix) == 6 && vendor != "" {
			ouiMap[prefix] = vendor
		}
	}
}

// LookupVendor returns the IEEE registry vendor name for a MAC (any separator), or "".
func LookupVendor(mac string) string {
	mac = strings.ToUpper(mac)
	var b strings.Builder
	for _, c := range mac {
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'F' {
			b.WriteRune(c)
		}
	}
	s := b.String()
	if len(s) < 6 {
		return ""
	}
	return ouiMap[s[:6]]
}
