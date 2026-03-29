package fingerprint

import (
	"encoding/binary"
	"net"
	"strconv"
)

// SynAckFeat is a decoded IPv4 SYN+ACK (passive TCP stack fingerprint inputs).
type SynAckFeat struct {
	TTL  int
	Win  uint16
	MSS  uint16
	WS   int  // -1 if absent
	SACK bool
	TS   bool
}

// ParseIPv4SYNACKPacket extracts TTL and TCP features from a raw IPv4 packet (incl. IP header).
func ParseIPv4SYNACKPacket(buf []byte) (SynAckFeat, bool) {
	var z SynAckFeat
	if len(buf) < 40 {
		return z, false
	}
	if buf[0]>>4 != 4 {
		return z, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if len(buf) < ihl+20 {
		return z, false
	}
	z.TTL = int(buf[8])
	tcp := buf[ihl:]
	if len(tcp) < 20 {
		return z, false
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || len(tcp) < doff {
		return z, false
	}
	z.Win = binary.BigEndian.Uint16(tcp[14:16])
	flags := tcp[13]
	if flags&0x12 != 0x12 {
		return z, false
	}
	z.WS = -1
	off := 20
	for off < doff {
		k := tcp[off]
		if k == 0 {
			break
		}
		if k == 1 {
			off++
			continue
		}
		if off+1 >= len(tcp) {
			break
		}
		optLen := int(tcp[off+1])
		if optLen < 2 || off+optLen > len(tcp) {
			break
		}
		switch k {
		case 2: // MSS
			if optLen >= 4 {
				z.MSS = binary.BigEndian.Uint16(tcp[off+2 : off+4])
			}
		case 3: // Window scale
			if optLen >= 3 {
				z.WS = int(tcp[off+2])
			}
		case 4: // SACK permitted
			z.SACK = true
		case 8: // Timestamps
			z.TS = true
		}
		off += optLen
	}
	return z, true
}

// FormatTCPStackHint builds a compact, stable string for records and os_tcp_stack parsing.
func FormatTCPStackHint(f SynAckFeat) string {
	s := "SYN-ACK ttl=" + strconv.Itoa(f.TTL) + " win=" + strconv.Itoa(int(f.Win))
	if f.MSS > 0 {
		s += " mss=" + strconv.Itoa(int(f.MSS))
	}
	if f.WS >= 0 {
		s += " ws=" + strconv.Itoa(f.WS)
	}
	if f.SACK {
		s += " sack"
	}
	if f.TS {
		s += " ts"
	}
	return s
}

// VerifySYNACKPorts checks that the packet is a SYN-ACK for our sport->dport handshake.
func VerifySYNACKPorts(buf []byte, expectedDst net.IP, sport, dport uint16) bool {
	if len(buf) < 40 {
		return false
	}
	if buf[0]>>4 != 4 {
		return false
	}
	ihl := int(buf[0]&0x0f) * 4
	if len(buf) < ihl+20 {
		return false
	}
	srcIP := net.IP(buf[12:16])
	if !srcIP.Equal(expectedDst) {
		return false
	}
	tcp := buf[ihl:]
	rsport := binary.BigEndian.Uint16(tcp[0:2])
	rdport := binary.BigEndian.Uint16(tcp[2:4])
	return rsport == dport && rdport == sport
}
