package fingerprint

import "testing"

func TestParseSMB1SessionSetupResponse(t *testing.T) {
	t.Parallel()
	// Minimal SMB1 Session Setup Response: header + WC=4 + 8 param bytes + ByteCount + 4-byte blob + UTF-16 strings.
	var b []byte
	hdr := make([]byte, 32)
	copy(hdr[0:4], []byte{0xFF, 'S', 'M', 'B'})
	hdr[4] = 0x73
	b = append(b, hdr...)
	b = append(b, 4) // WordCount = 4 words = 8 bytes
	// Parameters: AndX FF, Res 0, AndXOff 0, Action 0, SecurityBlobLength=4
	b = append(b, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00)
	byteCountPos := len(b)
	b = append(b, 0x00, 0x00) // ByteCount placeholder
	dataStart := len(b)
	b = append(b, 0xaa, 0xbb, 0xcc, 0xdd) // security blob
	// Native OS: "TestOS", UTF-16-LE + null
	for _, r := range "TestOS" {
		b = append(b, byte(r), 0)
	}
	b = append(b, 0, 0)
	// Native LAN: "LANMAN"
	for _, r := range "LANMAN" {
		b = append(b, byte(r), 0)
	}
	b = append(b, 0, 0)
	byteCount := len(b) - dataStart
	putU16(b, byteCountPos, uint16(byteCount))

	os, lan := parseSMB1SessionSetupResponse(b)
	if os != "TestOS" || lan != "LANMAN" {
		t.Fatalf("got %q / %q", os, lan)
	}
}

func putU16(buf []byte, off int, v uint16) {
	buf[off] = byte(v)
	buf[off+1] = byte(v >> 8)
}
