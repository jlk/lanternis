//go:build integration

package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func pingHost(ctx context.Context, ip string) bool {
	dst := net.ParseIP(ip)
	if dst == nil || dst.To4() == nil {
		return false
	}

	// Note: On macOS and most Linux setups this requires root/CAP_NET_RAW.
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	id := os.Getpid() & 0xffff
	seq := randomSeq()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("lanternis"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.WriteTo(b, &net.IPAddr{IP: dst}); err != nil {
		return false
	}

	// Read until we get our reply or timeout/cancel.
	buf := make([]byte, 1500)
	deadline := time.Now().Add(700 * time.Millisecond)
	for {
		if ctx.Err() != nil {
			return false
		}
		_ = c.SetReadDeadline(deadline)
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return false
		}
		_ = peer
		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if body.ID == id && body.Seq == seq {
			return true
		}
		// Otherwise, keep waiting within deadline for our reply.
	}
}

func randomSeq() int {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return int(time.Now().UnixNano() & 0xffff)
	}
	return int(binary.BigEndian.Uint16(b[:]))
}

