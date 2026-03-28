package fingerprint

import (
	"crypto/tls"
	"net/http"
	"time"
)

// DefaultHTTPClient returns an HTTP client suitable for LAN device URLs (HTTP and HTTPS with self-signed certs).
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
}
