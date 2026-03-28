# Active reachability: TCP (default) vs ICMP (integration)

Lanternis has two probe strategies:

| | **Default build** | **`integration` build** |
|---|-------------------|-------------------------|
| **Mechanism** | **Option B — TCP connect** to curated home/IoT ports (in parallel, per-host deadline), not a full port scan | **Option A — ICMP echo** (raw socket) |
| **Permissions** | Unprivileged | Often **root** / `CAP_NET_RAW` (see below) |
| **Tradeoff** | Misses silent hosts with no matching ports open; polite | Closer to a classic “ping sweep” |

**Scan modes** (`light` / `normal` / `thorough`) control both **parallel host workers** and **TCP port breadth** (see `internal/discovery/tcp_probe.go`: `PortsForTCPProfile` / `TCPProfileLight|Normal|Thorough`). The integration build ignores TCP profiles and uses ICMP only.

Diagnostics (`GET /api/diagnostics`) includes `tcp_probe_profiles` with the port lists per mode (default build).

Per-host results: **`GET /api/hosts`** includes **`open_ports`** (JSON array of strings): every probe-list port that accepted a TCP connect for that scan, sorted numerically. ICMP builds use `["icmp"]` when echo reply was seen.

If you want **real ICMP echo** probing, build/run with the `integration` build tag:

```bash
go run -tags=integration ./cmd/lanternis
```

## Permissions (why ICMP may “not work”)

ICMP echo requires creating a raw socket.

- **macOS**: typically requires running as **root**.

```bash
sudo go run -tags=integration ./cmd/lanternis
```

- **Linux**: either run as **root** or grant the binary `CAP_NET_RAW`.

Example (after building a binary):

```bash
go build -tags=integration -o lanternis ./cmd/lanternis
sudo setcap cap_net_raw+ep ./lanternis
./lanternis
```

## Notes

- The ICMP implementation is currently **IPv4-only**.
- This is intentionally behind a build tag so `go test ./...` remains non-privileged and deterministic.

