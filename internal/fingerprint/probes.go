package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var reHTMLTitle = regexp.MustCompile(`(?is)<title[^>]*>([^<]+)</title>`)

// FetchHTTPTitle performs a short GET to http://ip:port/ and returns trimmed title text, or "".
func FetchHTTPTitle(ctx context.Context, client *http.Client, ip, port string) (string, error) {
	if client == nil {
		client = DefaultHTTPClient()
	}
	u := fmt.Sprintf("http://%s/", net.JoinHostPort(ip, port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Lanternis/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 96*1024))
	if err != nil {
		return "", err
	}
	m := reHTMLTitle.FindSubmatch(body)
	if len(m) < 2 {
		return "", nil
	}
	return strings.TrimSpace(string(m[1])), nil
}

// TLSCertNames connects with InsecureSkipVerify and returns a representative DNS name from the leaf cert, or "".
func TLSCertNames(ctx context.Context, ip, port string) (string, error) {
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(ip, port), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         ip,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", nil
	}
	cert := st.PeerCertificates[0]
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0], nil
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return "", nil
}

// FetchSSHBanner reads one line from TCP ip:port (expected 22).
func FetchSSHBanner(ctx context.Context, ip, port string) (string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return "", err
	}
	defer c.Close()
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	line := strings.TrimSpace(string(buf[:n]))
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line, nil
}
