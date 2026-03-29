# Lanternis

**Lanternis** is a hobby/OSS tool for the household “IT person”: **LAN discovery**, honest device inventory, and (later) **evidence-backed** security intel—without pretending to know what the network does not reveal.

The **M1** vertical slice is in place: SQLite persistence, LAN discovery, a localhost-only HTTP API with CSRF on mutating routes, and audit logging. Scans record **per-run CIDR**, store **CIDR-scoped snapshots** for diffing, and the web UI shows **diff summary**, **new-open-ports** notices, and **export** of the latest diff as JSON. Fingerprinting is **IoT-oriented** (honest banners, UPnP, mDNS, SSDP, optional **deep**-mode raw TCP stack hints on Linux); **SNMP is explicitly out of scope**. See **`docs/ENGINEERING-PLAN.md`** and **`docs/FINGERPRINT-PLAN.md`** for package layout, security notes, and roadmap.

## Documentation

| Doc | Purpose |
|-----|---------|
| [`docs/INCEPTION.md`](docs/INCEPTION.md) | Why the project exists, principles, milestone summary |
| [`docs/ENGINEERING-PLAN.md`](docs/ENGINEERING-PLAN.md) | Packages, security, SQLite audit, tests, failure modes |
| [`docs/VULN-SCANNER-PLAN.md`](docs/VULN-SCANNER-PLAN.md) | Roadmap: findings (vendor/product/version), CPE, intel; SNMP scope rationale |
| [`docs/UI-PLAN.md`](docs/UI-PLAN.md) | Localhost console IA, states, accessibility, UI tokens |
| [`DESIGN.md`](DESIGN.md) | Visual system: color, type, spacing, motion, dark mode (source of truth for UI code) |
| [`TODOS.md`](TODOS.md) | Deferred work and follow-ups |

Design deep-dives and some QA artifacts also live under **`~/.gstack/projects/lanternis/`** on the author’s machine (see links in `docs/INCEPTION.md`).

## Built with gstack

Planning, review passes (office-hours, engineering/design plan reviews), and supporting artifacts for this project were produced using **[gstack](https://github.com/garrytan/gstack)**—agent skills and workflows for AI-assisted development (browse/QA, ship, retros, etc.). The **application code** here is ordinary Go; gstack mainly shaped **how** the plans and repo were iterated.

## Quick start

Requires [Go](https://go.dev/) 1.26+ (see `go.mod`).

```bash
go build -o lanternis ./cmd/lanternis
./lanternis
```

### Optional: `device_aliases.json` (name hints)

Place a file named **`device_aliases.json`** in the **same directory as your SQLite database** (the path you pass to `-db`, default `lanternis.db` in the current working directory). On startup the server loads it; malformed JSON is logged and user aliases are skipped.

Example:

```json
{
  "hostname_substrings": {
    "living-room-tv": "Living room Chromecast",
    "kitchen-plug": "Meross kitchen outlet"
  },
  "mac_prefixes": {
    "aa:bb:cc": "Office switch (user label)"
  }
}

```

Matching is case-insensitive for hostnames; MAC prefixes are normalized (`:` separators, lower case). These labels appear under **Name hints** on the host detail panel and in **`GET /api/host`** as `inferences`—they do **not** replace the main inventory label.

## License

[MIT](LICENSE)
