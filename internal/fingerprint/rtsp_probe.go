package fingerprint

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ProbeRTSPBanner sends a minimal OPTIONS and returns the Server header if present.
func ProbeRTSPBanner(ctx context.Context, ip, port string) (server string, ok bool) {
	ip = strings.TrimSpace(ip)
	port = strings.TrimSpace(port)
	if ip == "" || port == "" {
		return "", false
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(4 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	req := fmt.Sprintf("OPTIONS rtsp://%s:%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Lanternis/1.0\r\n\r\n", ip, port)
	if _, err := io.WriteString(conn, req); err != nil {
		return "", false
	}
	br := bufio.NewReader(io.LimitReader(conn, 2048))
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, cut := strings.Cut(line, ":")
		if cut && strings.EqualFold(strings.TrimSpace(k), "server") {
			v = strings.TrimSpace(v)
			if v != "" {
				return v, true
			}
		}
	}
	return "", false
}
