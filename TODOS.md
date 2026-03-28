# TODOS — Lanternis

Deferred from **CEO selective-expansion** review (**2026-03-22**). See `~/.gstack/projects/lanternis/ceo-plans/2026-03-22-lanternis-selective.md`.

## P2 — Soon after M1

- **ICMP / raw-socket spike** — **Done:** `docs/ICMP.md` OS matrix (macOS/Linux/Windows/WSL), examples, `ENGINEERING-PLAN.md` checklist ticked.
- **CI follow-up** — **Done:** `.github/workflows/ci.yml` runs `go test`, `go vet`, `gofmt` check, `go test -race`, and `go test -tags=integration` in parallel jobs.
- **First-run trust wizard** — **Done:** localhost modal + `app_kv` + `/api/setup/*`; optional **NVD API key** (local storage, `nvd_api_key` in setup complete); **retention copy** in modal (audit growth caps described; aligns with engineering plan).
- **Redacted support export** — **Done:** `POST /api/support/export` (CSRF) downloads JSON; About page button. Includes versions, probe mode, inventory **counts**, audit **types**, setup flags including **`nvd_api_key_configured`** (no secret values).

## P3 — M2 / pain-driven

**CEO cherry-picks (2026-03-28)** — **CIDR-scoped diff**, **diff export**, **dismiss-until-next-scan** for new-port banner, and **24h snooze** for that banner are **shipped**. **Timeline** and **metrics** remain deferred (below).

- **`DESIGN.md` or expanded tokens** — **Done (baseline):** root `DESIGN.md` + `docs/design-preview.html`; keep embedded CSS in sync with tokens when changing UI.
- **Dark mode** — **Done (console):** light/dark toggle + `prefers-color-scheme` when no saved preference; keep tokens aligned with `DESIGN.md` on edits.
- **Device fingerprinting** — **Plan:** [`docs/FINGERPRINT-PLAN.md`](docs/FINGERPRINT-PLAN.md). **Product target: L4** (manufacturer/model/firmware strings with evidence). Spine: UPnP `LOCATION` XML + HTTP(S)/TLS/SSH probes; OUI/mDNS/SSDP as ladder + merge; DHCP/p0f secondary; pluggable packs after **3+** heuristics.
- **Scan diff / history** — **Partially done:** last **N** snapshot runs retained; **GET `/api/scan/runs`** + **Recent scans** panel (id, times, mode, CIDR, status). **Still open:** flapping hosts, label-change emphasis, full **timeline** UI (deferred below).
- **New open-port alerts** — **Done (v1):** diff vs previous snapshot + localhost **banner**; dismiss per scan + **Snooze 24h**. Optional later: audit event on new ports.
- **CIDR-scoped scan diff** — **Done.**
- **Diff export** — **Done** (`GET /api/scan/diff`, `POST /api/scan/diff/export` with CSRF).
- **Scan history timeline (multi-scan UI)** — Rich timeline / beyond simple list. **Deferred post–P3 v1** (**CEO #3**); basic list is in place.
- **Scan metrics / counter** — Structured counter or metric for scan completions (beyond logs). **Deferred post–P3 v1** (**CEO #4**).

## Already in design doc (track during implementation)

- Multi-subnet / VLAN config (post-v0)  
- IPv6-first paths  
- Cloud LLM vendor + DPA if enabling cloud mode  
- Legal/compliance pass before wide distribution
