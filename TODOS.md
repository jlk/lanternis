# TODOS — Lanternis

Deferred from **CEO selective-expansion** review (**2026-03-22**). See `~/.gstack/projects/lanternis/ceo-plans/2026-03-22-lanternis-selective.md`.

## P2 — Soon after M1

- **ICMP / raw-socket spike** — **Done:** `docs/ICMP.md` OS matrix (macOS/Linux/Windows/WSL), examples, `ENGINEERING-PLAN.md` checklist ticked.
- **CI follow-up** — **Done:** `.github/workflows/ci.yml` runs `go test`, `go vet`, `gofmt` check, `go test -race`, and `go test -tags=integration` in parallel jobs.
- **First-run trust wizard** — **Done (M1):** localhost modal + `app_kv` + `/api/setup/`*; **still deferred:** optional NVD API key field, richer retention copy.
- **Redacted support export** — **Done:** `POST /api/support/export` (CSRF) downloads JSON; About page button. Includes versions, probe mode, inventory **counts**, audit **types** (no full paths, payloads, or per-host IPs).

## P3 — M2 / pain-driven

- `**DESIGN.md` or expanded tokens** — Promote `UI-PLAN` CSS variables into a design source file after first UI iteration; optional `/design-consultation`.
- **Dark mode** — `prefers-color-scheme` palette (deferred from UI plan).
- **Pluggable fingerprint providers** — Internal interface + disk-based packs after **3+** shipped heuristics prove the shape.
- **Scan diff / history** — Retain last **N** scans or time window; UI for new/removed/flapping hosts and label changes.
- **New open-port alerts** — Compare current `open_ports` (per host, from active probe) to the previous scan snapshot; surface notifications or a “new port since last scan” indicator (builds on scan history + `hosts.open_ports_json` diff). Optional: audit event or localhost banner when `ports_opened ⊄ ports_previous`.

## Already in design doc (track during implementation)

- Multi-subnet / VLAN config (post-v0)  
- IPv6-first paths  
- Cloud LLM vendor + DPA if enabling cloud mode  
- Legal/compliance pass before wide distribution

