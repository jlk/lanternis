# Engineering plan — Lanternis (M1 → M1a → C1)

**Locked by `/plan-eng-review`** — **2026-03-22**  
**Branch:** unknown (no `git` yet) · **Module:** `github.com/jlk/lanternis`

**Upstream docs:** design spec `~/.gstack/projects/lanternis/jlk-unknown-design-20260321-191134.md`, CEO plan `~/.gstack/projects/lanternis/ceo-plans/2026-03-22-lanternis-selective.md`, `TODOS.md`.

---

## Step 0 — Scope & complexity

### What already exists

- Stub `cmd/lanternis/main.go`, `go.mod`. **No** discovery, **no** DB, **no** HTTP server yet.

### Minimum path to M1 (vertical slice)

1. **SQLite** profile DB + migrations (`embed` or `golang-migrate` — pick one library in first PR).  
2. **ICMP sweep** worker with **CEO-mandated** politeness (caps, jitter, backoff, cancel).  
3. **Persist** `host` / `scan_run` rows + **audit_events** append-only semantics.  
4. **Loopback HTTP** + static/API for **table + scan controls**.  
5. **Tests:** pure-Go units for scheduler math + `httptest` for API; **no** ICMP in default CI (build tag `integration`).

### Complexity check

The **full** vision touches **>8** packages/files — **acceptable** if shipped as **one vertical slice** (M1) before splitting intel/LLM. **Do not** start C1/C2 until M1a discovery is stable on **macOS + Linux**.

### Search-before-building (summary)

- **ICMP in Go:** `net` + raw sockets are OS-specific; prefer a small **wrapper** with build tags or use a maintained dep after spike (**[Layer 2]** verify).  
- **SQLite:** `modernc.org/sqlite` or CGO `mattn/go-sqlite3` — prefer **pure Go** for cross-compile unless you need specific extensions (**[Layer 1]**).  
- **NVD client:** find maintained Go client or thin REST wrapper — don’t parse XML feeds by hand (**[Layer 1]**).

---

## Architecture (locked)

```
                    ┌─────────────────┐
  CLI flags ───────►│   cmd/lanternis  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ internal/    │   │ internal/    │   │ internal/    │
  │ httpserver   │   │ discovery    │   │ store        │
  │ :127.0.0.1   │   │ icmp+m1a*    │   │ sqlite +     │
  └──────┬───────┘   └──────┬───────┘   │ migrations   │
         │                  │          └──────┬───────┘
         │                  │                 │
         │                  └────────┬────────┘
         │                           │
         │                    ┌──────▼───────┐
         │                    │ audit_events │
         │                    │ (append-only │
         │                    │  INSERT only)│
         │                    └──────────────┘
         * M1a: arp, mdns, ssdp behind interfaces
```

### Process boundaries

- **Single binary**; **no** separate daemon required for v0.  
- **Discovery** runs in **goroutine pool** owned by an explicit **`ScanCoordinator`** (one place for caps/cancel).

---

## Data model (v0 sketch)

| Table / entity | Purpose |
|----------------|---------|
| `scan_runs` | id, started_at, ended_at, profile_id, mode (light/normal/thorough), cancel_requested |
| `hosts` | ip, last_seen, reachability, raw hints (mDNS name JSON), confidence, fingerprint blob |
| `intel_cache` | key, payload_json, fetched_at, ttl_class (aligns design NFRs) |
| `audit_events` | id, ts, event_type, payload_json **without secrets**; **INSERT-only** in app code |

**Retention:** prune `audit_events` **>90d** or **>100k** rows (CEO plan); same job can prune stale `intel_cache` by TTL.

### Audit storage decision (CEO open point — **LOCKED**)

**Use SQLite table `audit_events`** in the **same** DB file as inventory — one backup/export story, queryable for future UI. **Reject** parallel JSONL unless profiling shows SQLite append contention (unlikely at home scale).

---

## Localhost HTTP — security (non-negotiable)

| Topic | Rule |
|--------|------|
| **Bind** | `127.0.0.1` only (or `::1` if dual-stack later); **never** `0.0.0.0` in default config. |
| **CSRF** | Any **mutating** route (start scan, clear data, revoke creds) requires **CSRF token** (double-submit cookie + header) or **SameSite=Strict** session cookie + **Origin** check. **GET** must be safe. |
| **Static assets** | If embedding JS, **hash** or **no-cache** in dev; prod embed is single-binary friendly. |

---

## Discovery politeness (CEO accepted)

- **Semaphore** max concurrent ICMP workers (default **e.g. 32** — tune from spike).  
- **Batch** targets with **sleep+jitter** between batches (e.g. 10–50ms + random).  
- **Exponential backoff** on **permission errors** or **interface down**.  
- **Context cancel** propagates from UI/API to workers.  
- **Expose** in API: `scan_phase`, `completed`, `total`, `cancel_supported`.

---

## Error & failure modes (plan-level)

| Codepath | Failure | User sees | Log / audit |
|----------|---------|-----------|---------------|
| ICMP raw socket denied | permission error | “Run with privileges or use limited mode” | `audit_events` + structured error |
| DB locked / corrupt | sqlite busy | “Database error — see logs” | retry with backoff; surface once |
| NVD 429 | rate limit | “Intel temporarily rate-limited” + last cache time | audit fetch outcome |
| LLM (C2) invalid JSON | parse error | “Assistant unavailable” | **never** invent CVE row |

**CRITICAL (implementation gate):** UI must **not** show severity if `evidence[]` empty (design doc contract).

---

## Testing (locked matrix)

| Area | Kind | Notes |
|------|------|--------|
| Scan scheduler | **Unit** | deterministic fake clock / fake pinger |
| HTTP API | `httptest` | CSRF negative tests |
| Store | **Unit** | in-memory SQLite or temp file |
| ICMP end-to-end | **integration** tag | manual / CI opt-in |
| Intel clients | **Unit** + recorded **golden** HTTP | no live NVD in default CI |

**Friday-night test:** single command: `go test ./...` green + `go test -tags=integration ./...` optional locally.

---

## Performance

- **SQLite:** WAL mode; index on `hosts(ip)`, `audit_events(ts)`.  
- **Scan:** avoid **O(n²)**; batch writes (transaction per batch of hosts).  
- **Intel:** bounded concurrent fetches; respect NVD key quotas in design.

---

## Code layout (target)

```
cmd/lanternis/
internal/
  config/
  discovery/     # icmp, later m1a
  httpserver/    # routes, CSRF, embed FS optional
  store/         # sql, migrations
  audit/         # typed Append(event)
  intel/         # C1 — later
```

**Rule:** keep **M1** shippable with **`discovery` + `store` + `httpserver` + `audit`** only.

---

## NOT in scope (eng, v0)

- Remote admin / TLS reverse proxy (document “ssh -L” for power users).  
- Multi-user auth on localhost UI (single operator model).  
- Automated firmware push / remediation.  
- IPv6-first stack (defer per design).

---

## TODOS cross-check

`TODOS.md` already holds wizard, export, plugins, diff — **none** block M1. Add during implementation if needed:

- **Spike:** ICMP permission model per OS (document in `docs/`).  
- **CI:** GitHub Action `go test ./...` on push (when repo exists).

---

## Diagram — scan state machine

```
  [idle] --start--> [running] --done--> [idle]
     ^                  |
     +------cancel------+
```

Invalid: `start` while `running` without **cancel** or **queue** — **recommend:** reject second start with **409** + clear message.

---

## Completion checklist (for implementer)

- [ ] Migrations v1 with `hosts`, `scan_runs`, `audit_events`, `intel_cache` (cache can be empty stub)  
- [ ] Politeness defaults documented in `--help`  
- [ ] CSRF on mutating routes  
- [ ] `go test ./...` passes without network  
- [ ] Design doc `evidence[]` rule reflected in any future LLM handler  
- [x] ICMP permissions documented (`docs/ICMP.md`, OS matrix + Windows) and real ICMP probe available behind `-tags=integration`

---

## GSTACK REVIEW REPORT (eng + design)

| Review | Trigger | Status | Findings |
|--------|---------|--------|----------|
| Eng Review | `/plan-eng-review` | **RECORDED** | Architecture + test matrix + audit=SQLite locked in this file |
| CEO Review | prior session | CLEAR | Selective expansions recorded |
| Design Review | `/plan-design-review` | **RECORDED** | **`docs/UI-PLAN.md`** — IA, state table, journey, tokens, a11y |

**VERDICT:** **Implement M1** against **ENGINEERING-PLAN** + **UI-PLAN**; then **`/design-review`** on running localhost for visual QA.
