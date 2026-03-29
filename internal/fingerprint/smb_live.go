package fingerprint

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// FetchSMBNativeStrings performs SMB1 negotiate + session setup (anonymous extended security) and
// returns Native OS / Native LAN Manager strings when present (best-effort).
func FetchSMBNativeStrings(ctx context.Context, ip, port string) (nativeOS, nativeLAN string) {
	if port == "" {
		port = "445"
	}
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(8 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	negReq := buildSMB1Negotiate(1)
	if err := writeNBSS(conn, negReq); err != nil {
		return "", ""
	}
	negResp, err := readNBSS(conn)
	if err != nil || len(negResp) < 32 {
		return "", ""
	}
	if negResp[4] == 0xfe && negResp[5] == 'S' && negResp[6] == 'M' && negResp[7] == 'B' {
		// SMB2+ only — no SMB1 session-setup strings via this path.
		return "", ""
	}
	if negResp[4] != 0xff || negResp[5] != 'S' || negResp[6] != 'M' || negResp[7] != 'B' || negResp[8] != 0x72 {
		return "", ""
	}
	uid := binary.LittleEndian.Uint16(negResp[26:28])

	blob, err := buildSMBSessionSecurityBlob()
	if err != nil {
		return "", ""
	}
	sessReq := buildSMB1SessionSetup(uid, 2, blob)
	if err := writeNBSS(conn, sessReq); err != nil {
		return "", ""
	}
	sessResp, err := readNBSS(conn)
	if err != nil || len(sessResp) < 33 {
		return "", ""
	}
	return parseSMB1SessionSetupResponse(sessResp)
}

func writeNBSS(w io.Writer, payload []byte) error {
	if len(payload) > 0xffffff {
		return io.ErrShortBuffer
	}
	var hdr [4]byte
	hdr[0] = 0
	hdr[1] = byte(len(payload) >> 16)
	hdr[2] = byte(len(payload) >> 8)
	hdr[3] = byte(len(payload))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readNBSS(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	n := int(uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
	if n <= 0 || n > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func buildSMB1Header(cmd byte, uid, mid uint16) []byte {
	h := make([]byte, 32)
	h[0], h[1], h[2], h[3] = 0xff, 'S', 'M', 'B'
	h[4] = cmd
	// Flags2: Unicode, NT status, long names
	binary.LittleEndian.PutUint16(h[10:12], 0xc803)
	binary.LittleEndian.PutUint16(h[24:26], 1) // PID low
	binary.LittleEndian.PutUint16(h[26:28], uid)
	binary.LittleEndian.PutUint16(h[28:30], mid)
	return h
}

func buildSMB1Negotiate(mid uint16) []byte {
	// Dialect: NT LM 0.12
	dialect := []byte{0x02}
	dialect = append(dialect, "NT LM 0.12\x00"...)
	hdr := buildSMB1Header(0x72, 0, mid)
	var b []byte
	b = append(b, hdr...)
	b = append(b, 0) // WordCount
	bcOff := len(b)
	b = append(b, 0, 0) // ByteCount
	dataOff := len(b)
	b = append(b, dialect...)
	putU16LE(b, bcOff, uint16(len(b)-dataOff))
	return b
}

func buildSMB1SessionSetup(uid uint16, mid uint16, secBlob []byte) []byte {
	hdr := buildSMB1Header(0x73, uid, mid)
	// Session Setup AndX — extended security: 13 parameter words (MS-CIFS).
	p := make([]byte, 27)
	p[0] = 13
	binary.LittleEndian.PutUint16(p[1:3], 0x00ff) // AndX 0xFF, Reserved 0
	binary.LittleEndian.PutUint16(p[3:5], 0)     // AndXOffset
	binary.LittleEndian.PutUint16(p[5:7], 0xffff)
	binary.LittleEndian.PutUint16(p[7:9], 10)
	binary.LittleEndian.PutUint16(p[9:11], 0)
	binary.LittleEndian.PutUint32(p[11:15], 0)
	binary.LittleEndian.PutUint16(p[15:17], uint16(len(secBlob))) // SecurityBlobLength (OEM len field)
	binary.LittleEndian.PutUint16(p[17:19], 0)                     // UnicodePasswordLen
	binary.LittleEndian.PutUint32(p[19:23], 0)                     // Reserved
	binary.LittleEndian.PutUint32(p[23:27], 0x800000d5)            // Capabilities

	b := make([]byte, 0, len(hdr)+len(p)+2+len(secBlob))
	b = append(b, hdr...)
	b = append(b, p...)
	bcOff := len(b)
	b = append(b, 0, 0)
	dataOff := len(b)
	b = append(b, secBlob...)
	putU16LE(b, bcOff, uint16(len(b)-dataOff))
	return b
}

func putU16LE(buf []byte, off int, v uint16) {
	buf[off] = byte(v)
	buf[off+1] = byte(v >> 8)
}
