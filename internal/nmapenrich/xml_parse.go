package nmapenrich

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Limits defend against malformed or hostile XML (entity expansion, huge allocations).
const (
	maxNmapXMLInputBytes = 8 << 20 // single-host -oX is far smaller; bounds memory / decode cost
	maxPortsPerHost      = 512
	maxScriptsPerPort    = 64
)

// xmlRoot is nmap -oX document root (<nmaprun>).
type xmlRoot struct {
	XMLName xml.Name  `xml:"nmaprun"`
	Hosts   []xmlHost `xml:"host"`
}

type xmlHost struct {
	Ports xmlPorts `xml:"ports"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   string   `xml:"portid,attr"`
	State    xmlState `xml:"state"`
	Service  xmlSvc   `xml:"service"`
	Scripts  []xmlScr `xml:"script"`
}

type xmlState struct {
	State string `xml:"state,attr"`
}

type xmlSvc struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	Extrainfo string `xml:"extrainfo,attr"`
}

type xmlScr struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ParsedPort is one open port line from Nmap XML.
type ParsedPort struct {
	Proto     string
	Port      string
	Name      string
	Product   string
	Version   string
	Extrainfo string
	Scripts   map[string]string
}

// ErrNmapXMLRejected is returned when XML fails structural safety checks (not a valid nmap -oX document).
var ErrNmapXMLRejected = errors.New("nmap xml: rejected for safety")

// ParseNmapXML extracts open port service and script rows from nmap -oX output.
// Input is bounded; DTD entity declarations are rejected to avoid parser-based expansion attacks.
// Data is still treated as untrusted for downstream storage (truncation in callers).
func ParseNmapXML(r io.Reader) ([]ParsedPort, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxNmapXMLInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxNmapXMLInputBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrNmapXMLRejected, maxNmapXMLInputBytes)
	}
	if err := validateNmapXMLBytes(b); err != nil {
		return nil, err
	}

	var run xmlRoot
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	if err := dec.Decode(&run); err != nil {
		return nil, err
	}
	if len(run.Hosts) == 0 {
		return nil, nil
	}
	rawPorts := run.Hosts[0].Ports.Ports
	if len(rawPorts) > maxPortsPerHost {
		rawPorts = rawPorts[:maxPortsPerHost]
	}

	var out []ParsedPort
	for _, p := range rawPorts {
		st := strings.ToLower(strings.TrimSpace(p.State.State))
		if st != "open" && st != "open|filtered" {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		portID := strings.TrimSpace(p.PortID)
		if portID == "" {
			continue
		}
		pp := ParsedPort{
			Proto:     proto,
			Port:      portID,
			Name:      strings.TrimSpace(p.Service.Name),
			Product:   strings.TrimSpace(p.Service.Product),
			Version:   strings.TrimSpace(p.Service.Version),
			Extrainfo: strings.TrimSpace(p.Service.Extrainfo),
			Scripts:   make(map[string]string),
		}
		scripts := p.Scripts
		if len(scripts) > maxScriptsPerPort {
			scripts = scripts[:maxScriptsPerPort]
		}
		for _, sc := range scripts {
			id := strings.TrimSpace(sc.ID)
			if id == "" {
				continue
			}
			outStr := strings.TrimSpace(sc.Output)
			if outStr != "" {
				pp.Scripts[id] = truncateRunes(outStr, 800)
			}
		}
		out = append(out, pp)
	}
	return out, nil
}

func validateNmapXMLBytes(b []byte) error {
	if bytes.IndexByte(b, 0) >= 0 {
		return fmt.Errorf("%w: NUL byte in document", ErrNmapXMLRejected)
	}
	if dtdInternalSubsetDeclaresEntity(b) {
		return fmt.Errorf("%w: DTD internal subset contains ENTITY declaration", ErrNmapXMLRejected)
	}
	return nil
}

// dtdInternalSubsetDeclaresEntity detects <!ENTITY / <!ENTITIES inside a DOCTYPE internal subset [ ... ].
// Legitimate nmap -oX uses <!DOCTYPE nmaprun> or SYSTEM to nmap.dtd without an internal subset that
// declares entities; rejecting ENTITY here blocks billion-laughs–style expansion without scanning
// element bodies (avoids false positives on script output that mentions "<!ENTITY" as text).
func dtdInternalSubsetDeclaresEntity(b []byte) bool {
	i := 0
	for i < len(b) {
		j := indexCaseInsensitive(b, i, "<!DOCTYPE")
		if j < 0 {
			return false
		}
		k := j + len("<!DOCTYPE")
		// Find '[' starting internal subset (if any).
		bracket := indexByteFrom(b, k, '[')
		if bracket < 0 {
			gt := indexByteFrom(b, k, '>')
			if gt < 0 {
				return true // malformed DOCTYPE; reject
			}
			i = gt + 1
			continue
		}
		closeIdx := indexClosingBracketOfInternalSubset(b, bracket)
		if closeIdx < 0 {
			// Malformed; treat as unsafe.
			return true
		}
		subset := b[bracket : closeIdx+1]
		if indexEntityDeclInSubset(subset) >= 0 {
			return true
		}
		i = closeIdx + 1
	}
	return false
}

func indexByteFrom(b []byte, start int, c byte) int {
	for i := start; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// indexClosingBracketOfInternalSubset returns index of ']' that closes the subset opened at bracket '['.
func indexClosingBracketOfInternalSubset(b []byte, bracket int) int {
	if bracket < 0 || bracket >= len(b) || b[bracket] != '[' {
		return -1
	}
	inSQuote, inDQuote := false, false
	depth := 1
	for i := bracket + 1; i < len(b); i++ {
		c := b[i]
		if inSQuote {
			if c == '\'' {
				inSQuote = false
			}
			continue
		}
		if inDQuote {
			if c == '"' {
				inDQuote = false
			}
			continue
		}
		switch c {
		case '\'':
			inSQuote = true
		case '"':
			inDQuote = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// indexEntityDeclInSubset finds <!ENTITY (case-insensitive, XML whitespace allowed) inside subset.
func indexEntityDeclInSubset(subset []byte) int {
	for i := 0; i < len(subset); i++ {
		if subset[i] != '<' || i+2 >= len(subset) || subset[i+1] != '!' {
			continue
		}
		j := i + 2
		for j < len(subset) && isXMLSpace(subset[j]) {
			j++
		}
		if j+6 <= len(subset) && asciiEqualFoldASCII(subset[j:j+6], []byte("ENTITY")) {
			return i
		}
	}
	return -1
}

func isXMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func asciiEqualFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		c1, c2 := a[i], b[i]
		if c1 >= 'A' && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

func indexCaseInsensitive(b []byte, start int, needle string) int {
	nb := []byte(needle)
	if len(nb) == 0 {
		return 0
	}
	for i := start; i+len(nb) <= len(b); i++ {
		if asciiEqualFoldASCII(b[i:i+len(nb)], nb) {
			return i
		}
	}
	return -1
}

func truncateRunes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	return string(rs[:max]) + "…"
}
