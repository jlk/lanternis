package fingerprint

import (
	"encoding/binary"
	"unicode/utf16"
)

// parseSMB1SessionSetupResponse extracts Native OS and Native LAN Manager from an
// SMB_COM_SESSION_SETUP_ANDX (0x73) response. Handles NT LM 0.12 extended security:
// Unicode null-terminated strings after the security blob.
func parseSMB1SessionSetupResponse(buf []byte) (nativeOS, nativeLAN string) {
	if len(buf) < 36 {
		return "", ""
	}
	if buf[0] != 0xFF || buf[1] != 'S' || buf[2] != 'M' || buf[3] != 'B' || buf[4] != 0x73 {
		return "", ""
	}
	wc := int(buf[32])
	if wc < 4 {
		return "", ""
	}
	paramLen := wc * 2
	if len(buf) < 33+paramLen+2 {
		return "", ""
	}
	secLen := int(binary.LittleEndian.Uint16(buf[33+paramLen-2 : 33+paramLen]))
	byteCount := int(binary.LittleEndian.Uint16(buf[33+paramLen : 33+paramLen+2]))
	dataOff := 33 + paramLen + 2
	if dataOff+byteCount > len(buf) || byteCount < 0 {
		return "", ""
	}
	data := buf[dataOff : dataOff+byteCount]
	if secLen < 0 || secLen > len(data) {
		return "", ""
	}
	rest := data[secLen:]
	if len(rest) >= 1 && len(rest)%2 != 0 {
		rest = rest[1:]
	}
	s0, rest := readUTF16Z(rest)
	s1, _ := readUTF16Z(rest)
	return s0, s1
}

func readUTF16Z(b []byte) (string, []byte) {
	if len(b) < 2 {
		return "", b
	}
	var runes []uint16
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			return string(utf16.Decode(runes)), b[i+2:]
		}
		runes = append(runes, u)
	}
	return "", b
}
