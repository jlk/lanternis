package fingerprint

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// RDP client connection request (TPKT + X.224 Connection Request) — minimal, no cookie.
var rdpConnReq = []byte{
	0x03, 0x00, 0x00, 0x13,
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
}

// FetchRDPNegotiationHint reads the first server response after the standard RDP connection request.
// Returns a short human-readable summary (best-effort; not all servers reply usefully).
func FetchRDPNegotiationHint(ctx context.Context, ip, port string) string {
	if port == "" {
		port = "3389"
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(rdpConnReq); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 11 {
		return ""
	}
	return summarizeRDPResponse(buf[:n])
}

func summarizeRDPResponse(b []byte) string {
	// TPKT: 0x03 version, length BE at 2-3
	if len(b) < 11 || b[0] != 0x03 {
		return ""
	}
	tpktLen := int(binary.BigEndian.Uint16(b[2:4]))
	if tpktLen > 0 && tpktLen <= len(b) {
		b = b[:tpktLen]
	}
	// Walk TPKT payloads for X.224 CC / RDP negotiation
	rest := b[4:]
	if len(rest) < 2 {
		return ""
	}
	// X.224 length includes LI; Connection Confirm is 0xd0
	if rest[1] == 0xd0 && len(rest) >= 11 {
		// Skip CC fixed part; remainder may contain RDP negotiation
		ccLen := int(rest[0])
		if ccLen > len(rest) {
			ccLen = len(rest)
		}
		rest = rest[ccLen:]
	}
	sel := findRDPSelectedProtocol(b)
	if sel < 0 {
		if len(b) >= 20 {
			return "RDP (handshake observed)"
		}
		return ""
	}
	var parts []string
	parts = append(parts, "RDP")
	if sel&0x01 != 0 {
		parts = append(parts, "SSL")
	}
	if sel&0x02 != 0 {
		parts = append(parts, "CredSSP")
	}
	if sel&0x08 != 0 {
		parts = append(parts, "Early")
	}
	return strings.Join(parts, " · ")
}

// findRDPSelectedProtocol scans for RDP_NEG_RSP (type 0x02) and returns selectedProtocol LE, or -1.
func findRDPSelectedProtocol(b []byte) int {
	for i := 0; i+8 < len(b); i++ {
		if b[i] != 0x02 {
			continue
		}
		// RDP_NEG_RSP: type 0x02, flags, length LE, selectedProtocol LE
		length := int(binary.LittleEndian.Uint16(b[i+2 : i+4]))
		if length < 8 || i+length > len(b) {
			continue
		}
		sel := int(binary.LittleEndian.Uint32(b[i+4 : i+8]))
		return sel
	}
	return -1
}
