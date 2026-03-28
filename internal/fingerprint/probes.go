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

// FetchHTTPIndexMeta performs a GET to scheme://ip:port/ and returns HTML title and Server header when present.
// Non-2xx responses still contribute Server / body (many appliances return titles on 401/404).
func FetchHTTPIndexMeta(ctx context.Context, client *http.Client, scheme, ip, port string) (title, server string, err error) {
	if client == nil {
		client = DefaultHTTPClient()
	}
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("unsupported scheme %q", scheme)
	}
	u := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Lanternis/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	server = strings.TrimSpace(resp.Header.Get("Server"))
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 96*1024))
	if rerr != nil {
		return "", server, rerr
	}
	m := reHTMLTitle.FindSubmatch(body)
	if len(m) >= 2 {
		title = strings.TrimSpace(string(m[1]))
	}
	if server != "" || title != "" {
		return title, server, nil
	}
	if resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("http %d", resp.StatusCode)
	}
	return "", "", nil
}

// FetchHTTPTitle performs a short GET to http://ip:port/ and returns trimmed title text, or "".
func FetchHTTPTitle(ctx context.Context, client *http.Client, ip, port string) (string, error) {
	t, _, err := FetchHTTPIndexMeta(ctx, client, "http", ip, port)
	return t, err
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
