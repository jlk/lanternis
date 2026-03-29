package fingerprint

import (
	"encoding/binary"
	"testing"
)

func TestParseIPv4SYNACKPacket(t *testing.T) {
	t.Parallel()
	// IPv4 (20) + TCP header 32 bytes (doff=8): SYN+ACK with MSS 1460, WS 7, SACK permitted.
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 52) // total length
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{192, 168, 1, 1})

	tcp := make([]byte, 32)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 12345)
	tcp[12] = 0x80 // data offset 8
	tcp[13] = 0x12 // SYN+ACK
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	o := 20
	tcp[o+0] = 2
	tcp[o+1] = 4
	binary.BigEndian.PutUint16(tcp[o+2:o+4], 1460)
	o += 4
	tcp[o] = 1 // NOP
	o++
	tcp[o+0] = 3
	tcp[o+1] = 3
	tcp[o+2] = 7
	o += 3
	tcp[o+0] = 4
	tcp[o+1] = 2
	o += 2
	tcp[o+0] = 1
	tcp[o+1] = 1 // NOP NOP pad

	pkt := append(append([]byte{}, ip...), tcp...)

	feat, ok := ParseIPv4SYNACKPacket(pkt)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if feat.TTL != 64 || feat.MSS != 1460 || feat.WS != 7 || !feat.SACK || feat.TS {
		t.Fatalf("feat=%+v", feat)
	}
}
