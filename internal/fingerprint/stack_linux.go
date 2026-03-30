//go:build linux

package fingerprint

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// probeTCPStackHint sends a raw TCP SYN, reads SYN+ACK, decodes options, and optionally matches heuristics.
func probeTCPStackHint(ctx context.Context, ip, dport string) string {
	if dport == "" {
		dport = "80"
	}
	var dp uint16
	if _, err := fmt.Sscanf(dport, "%d", &dp); err != nil || dp == 0 {
		return ""
	}
	dst := net.ParseIP(ip)
	if dst == nil || dst.To4() == nil {
		return ""
	}
	dst4 := dst.To4()

	localIP := localIPv4For(dst4)
	if localIP == nil {
		return ""
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return ""
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return ""
	}

	sport := uint16(32768 + (uint16(time.Now().UnixNano()) % 28000))
	seq := uint32(time.Now().UnixNano())

	pkt := buildRawSYN(localIP, dst4, sport, dp, seq)
	sa := &unix.SockaddrInet4{Port: 0, Addr: [4]byte{dst4[0], dst4[1], dst4[2], dst4[3]}}
	if err := unix.Sendto(fd, pkt, 0, sa); err != nil {
		return ""
	}

	recvDeadline := 2 * time.Second
	if d, ok := ctx.Deadline(); ok {
		recvDeadline = time.Until(d)
		if recvDeadline < 0 {
			recvDeadline = 0
		}
		if recvDeadline > 5*time.Second {
			recvDeadline = 5 * time.Second
		}
	}
	tv := unix.NsecToTimeval(recvDeadline.Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 4096)
	for range 64 {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return ""
		}
		if !VerifySYNACKPorts(buf[:n], dst4, sport, dp) {
			continue
		}
		feat, ok := ParseIPv4SYNACKPacket(buf[:n])
		if !ok {
			continue
		}
		hint := FormatTCPStackHint(feat)
		if fam, det, _, match := matchSynAckRules(feat); match {
			hint = AppendTCPGuess(hint, fam, det)
		}
		return hint
	}
	return ""
}

func localIPv4For(dst net.IP) net.IP {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "1"))
	if err != nil {
		return nil
	}
	defer c.Close()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || la.IP == nil {
		return nil
	}
	return la.IP.To4()
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		if i+1 < len(b) {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		} else {
			sum += uint32(b[i]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(pseudo, tcp []byte) uint16 {
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(tcp); i += 2 {
		if i+1 < len(tcp) {
			sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
		} else {
			sum += uint32(tcp[i]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildRawSYN(src, dst net.IP, sport, dport uint16, seq uint32) []byte {
	ihl := uint8(5)
	tcpLen := 20
	totalLen := int(ihl)*4 + tcpLen
	ip := make([]byte, 20)
	ip[0] = (4 << 4) | ihl
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], uint16(time.Now().UnixNano()&0xffff))
	ip[6], ip[7] = 0x40, 0 // don't fragment
	ip[8] = 64             // TTL
	ip[9] = unix.IPPROTO_TCP
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	tcp[12] = 0x50                                // data offset 5
	tcp[13] = 0x02                                // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window
	tcp[16], tcp[17] = 0, 0

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(pseudo, tcp))

	out := make([]byte, 0, totalLen)
	out = append(out, ip...)
	out = append(out, tcp...)
	return out
}
