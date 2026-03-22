# Inception — Lanternis

This file records **why the project exists** and **how it was shaped** in early conversations (office-hours style design work and follow-ups). It is **narrative**, not a full spec. For architecture, milestones, stack, and NFRs, use the **design document** linked below.

## Canonical design spec

**Path (gstack):** `~/.gstack/projects/lanternis/jlk-unknown-design-20260321-191134.md`  
**Filename:** `jlk-unknown-design-20260321-191134.md`  
**Status:** DRAFT (as of last update to that file)

## CEO plan (selective expansion)

**Path (gstack):** `~/.gstack/projects/lanternis/ceo-plans/2026-03-22-lanternis-selective.md`  
Cherry-picks: **accepted** scan-kindness + SQLite audit trail; **deferred** items listed in repo **`TODOS.md`**.

## Engineering plan

**In-repo:** `docs/ENGINEERING-PLAN.md` — package layout, SQLite audit lock, localhost security, test matrix, failure modes.  
**QA test plan (gstack):** `~/.gstack/projects/lanternis/jlk-unknown-test-plan-20260322-eng.md`

## UI plan (design review)

**In-repo:** `docs/UI-PLAN.md` — information architecture, interaction states, copy tone, CSS variables, accessibility/responsive rules for the localhost console.

Copy or symlink that file into `docs/` later if you want everything versioned in-repo; until then, treat this repo’s `docs/` as **project-local** narrative and keep the gstack copy as the **detailed** source of truth.

## Problem we’re solving

Homes accumulate an **involuntary IT person**—often whoever others ask when **printing** breaks, or whoever **installed** the smart gear. As **IoT** spreads, **device count** and **brand fragmentation** exceed what one person can track with ad hoc tabs and apps. **Enterprise** NMS-style tools are **too heavy** for typical households.

**Lanternis** targets **discovery** and **assisted safety**: see what’s on the **LAN** (especially **thermostats, cameras, APs**), then help that admin with **honest** posture and **up-to-date** awareness—using **OSS** and **external vuln feeds**, not a hand-maintained CVE database.

## Product principles (from early agreement)

1. **Honest inventory first** — show what’s found, even if only an **IP**; no invented labels.  
2. **Layered discovery** — **ICMP** alone isn’t enough; **ARP/neighbor**, **mDNS**, **SSDP** (and similar) matter for real homes.  
3. **Evidence-backed risk** — **NVD**, **OSV**, **vendor** sources; **LLM** for interpretation and next steps with **citations**, not as the sole authority.  
4. **Credentials optional** — deeper checks only with clear consent; **no** silent mass remediation in **v0**.

**Chosen approach (design doc):** **Approach B** — layered discovery + **intel connectors** + **LLM copilot** (Phase **C2** after deterministic **C1**).

## Milestones (summary)

| Phase | Intent |
|--------|--------|
| **M1** | ICMP sweep + results model + UI with **unknown** rows, no fake names |
| **M1a** | Passive / host-assisted discovery when stable per OS |
| **M2** | Richer **IoT** identification where fingerprints exist |

**v0** in the design doc is scoped through **M1a** unless you expand it.

## Technical stack (locked in design)

- **Go** 1.22+, single binary, macOS / Linux / Windows  
- **CLI** + **localhost** web UI  
- **SQLite** per profile  
- **OS keychain** (or equivalent) for secrets  
- **LLM:** local (e.g. Ollama) **optional**, default **off**; cloud only with opt-in  
- **Contracts:** JSON Schema for **`device_record` v1** / **`llm_risk` v1**, semver on breaks  

**Go module (this repo):** `github.com/jlk/lanternis` — change the module path in `go.mod` if your GitHub identity differs.

## Naming — from “home-scanner” to **Lanternis**

Early working title: **home-scanner** (folder name may still reflect that). Many public names were **rejected** after collision checks: e.g. **Hearthguard** (Fail-Safe **HearthGuard**), **Patchboard** (music + API ecosystems), **Lanterne** (fleet ops app), **Phare** / **luminet** / **luminex** / **luminode** (existing security, telecom, biotech, lighting products), **Lumine** (Genshin + other uses), **Lumis** (syntax highlighter + other brands).

**Lanternis** was chosen as an **invented**, **Lanterne-adjacent** name with **cleaner** search/GitHub space; optional tagline: *A small light on your LAN.*

## Repo layout note

- **Code:** `cmd/lanternis/` (entrypoint); expand per design phases.  
- **Docs:** `docs/` — start with this **INCEPTION**; add architecture, ADRs, or a copied design spec as you go.

## What this document is not

- Not a substitute for the **full design doc** (NFRs, data retention, intel degradation, legal notes, reviewer concerns).  
- Not a transcript; it **summarizes** decisions and **points** to the spec.

---

*Written from project inception conversations, March 2026.*
