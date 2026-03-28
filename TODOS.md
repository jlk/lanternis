# TODOS — Lanternis

Deferred from **CEO selective-expansion** review (**2026-03-22**). See `~/.gstack/projects/lanternis/ceo-plans/2026-03-22-lanternis-selective.md`.

## P2 — Soon after M1

- **ICMP / raw-socket spike** — Document macOS/Linux/Windows permission model; link from `docs/ENGINEERING-PLAN.md` checklist.
- **CI follow-up** — Extend GitHub Actions beyond baseline `go test ./...` (e.g., linting, race detector, and optional integration-tag job).
- **First-run trust wizard** — **Done (M1):** localhost modal + `app_kv` + `/api/setup/*`; **still deferred:** optional NVD API key field, richer retention copy.
- **Redacted support export** — One-click bundle for GitHub issues: versions, capability flags, inventory summary, error codes; **no** secrets; optional opt-in for extra diagnostics.

## P3 — M2 / pain-driven

- `**DESIGN.md` or expanded tokens** — Promote `UI-PLAN` CSS variables into a design source file after first UI iteration; optional `/design-consultation`.
- **Dark mode** — `prefers-color-scheme` palette (deferred from UI plan).
- **Pluggable fingerprint providers** — Internal interface + disk-based packs after **3+** shipped heuristics prove the shape.
- **Scan diff / history** — Retain last **N** scans or time window; UI for new/removed/flapping hosts and label changes.

## Already in design doc (track during implementation)

- Multi-subnet / VLAN config (post-v0)  
- IPv6-first paths  
- Cloud LLM vendor + DPA if enabling cloud mode  
- Legal/compliance pass before wide distribution

