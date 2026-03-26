# ICMP probing (integration build)

Lanternis uses a **safe TCP connect hint** by default to avoid raw-socket permission issues during development.

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

