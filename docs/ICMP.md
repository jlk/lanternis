# Active reachability: TCP (default) vs ICMP (integration)

Lanternis has two probe strategies:

| | **Default build** | **`integration` build** |
|---|-------------------|-------------------------|
| **Mechanism** | **Option B — TCP connect** to curated home/IoT ports (in parallel, per-host deadline), not a full port scan | **Option A — ICMP echo** (raw socket) |
| **Permissions** | Unprivileged | Elevated privileges often required (see [OS matrix](#icmp-permissions-by-os)) |
| **Tradeoff** | Misses silent hosts with no matching ports open; polite | Closer to a classic “ping sweep” |

**Scan modes** (`light` / `normal` / `thorough` / `deep`) control both **parallel host workers** and **TCP port breadth** (see `internal/discovery/tcp_probe.go`: `PortsForTCPProfile` / `TCPProfileLight|Normal|Thorough|Deep`). **`deep`** uses the same port list as **thorough** with longer per-host connect budgets and enables optional raw TCP stack fingerprinting in the fingerprint pass on Linux. The integration build ignores TCP profiles and uses ICMP only.

Diagnostics (`GET /api/diagnostics`) includes `tcp_probe_profiles` with the port lists per mode (default build).

Per-host results: **`GET /api/hosts`** includes **`open_ports`** (JSON array of strings): every probe-list port that accepted a TCP connect for that scan, sorted numerically. ICMP builds use `["icmp"]` when echo reply was seen.

If you want **real ICMP echo** probing, build/run with the `integration` build tag:

```bash
go run -tags=integration ./cmd/lanternis
```

## ICMP permissions by OS

ICMP echo uses a **raw IP socket** (`SOCK_RAW` / `IPPROTO_ICMP`). OS policy determines whether unprivileged processes may open it. This is a **spike summary** for troubleshooting; it is not legal advice.

| OS | Typical requirement | Notes |
|----|---------------------|--------|
| **macOS** | Run as **root** (`sudo`) for raw ICMP with Go’s `x/net/icmp` listener | System Integrity Protection and socket policy generally block unprivileged raw ICMP in release builds. |
| **Linux** | **`CAP_NET_RAW`** on the binary (preferred) or run as **root** | Example: `sudo setcap cap_net_raw+ep ./lanternis` after `go build -tags=integration`. |
| **Windows** | Often **Administrator** elevation for raw sockets | Run the terminal or binary **as Administrator**. Group policy / Defender can still block or prompt. If ICMP fails, use the **default TCP build** for development. |
| **WSL (Linux on Windows)** | Treat as **Linux**: capability or root inside the WSL distro | Raw sockets behave like Linux; paths and `setcap` apply inside WSL, not to Windows host binaries. |

### Examples

**macOS** (root):

```bash
sudo go run -tags=integration ./cmd/lanternis
```

**Linux** (capability on binary):

```bash
go build -tags=integration -o lanternis ./cmd/lanternis
sudo setcap cap_net_raw+ep ./lanternis
./lanternis
```

**Windows** (elevated shell):

```powershell
# Run PowerShell or cmd as Administrator, then:
go run -tags=integration ./cmd/lanternis
```

## Why ICMP may “not work”

- Process lacks **raw socket** permission (see table above).
- **Firewall** or security software blocking ICMP or raw sockets.
- **IPv4-only** implementation today — no ICMPv6 in this build tag path.

## Notes

- The ICMP implementation is currently **IPv4-only**.
- The `integration` tag keeps `go test ./...` **without** raw sockets by default; CI runs default + `-tags=integration` compile/test.
- For GitHub issues, use **`POST /api/support/export`** (CSRF-protected) to download a **redacted** JSON bundle (versions, probe mode, inventory **counts**, audit **types** — no full paths or per-host IPs). See the Diagnostics / About page in the UI.

## See also

- `docs/ENGINEERING-PLAN.md` — completion checklist (ICMP doc + integration probe).
- `go test -tags=integration ./...` — ensures the ICMP code path builds in CI.
