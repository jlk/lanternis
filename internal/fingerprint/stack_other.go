//go:build !linux

package fingerprint

import "context"

// probeTCPStackHint returns SYN-ACK TTL and window (Linux raw sockets only). Stub on non-Linux.
func probeTCPStackHint(_ context.Context, _, _ string) string {
	return ""
}
