# UI plan — Lanternis localhost console

**From `/plan-design-review`** — **2026-03-22**  
**Branch:** unknown · **Calibrates against:** `docs/ENGINEERING-PLAN.md` · **No `DESIGN.md`** — tokens below are the **v0 design minimum**.

---

## Step 0 — Design scope & rating

- **UI scope:** **Yes** — localhost **device table**, **scan controls**, minimal **settings/status**, future **intel rows** (empty-safe).  
- **Initial design completeness:** **4/10** (engineering plan named routes but not **hierarchy**, **states**, or **voice**).  
- **Target after this doc:** **8.5/10** for **M1** (ship-ready spec); **10/10** needs **user testing** and optional **`DESIGN.md`**.

**What a 10 looks like here:** A tired household admin trusts the screen in **30 seconds**: knows **what’s scanning**, **what’s uncertain**, and **what to do next**—with **no** fake alarms and **no** “dashboard cosplay.”

---

## Design principles (Lanternis-specific)

1. **Utility, not marketing** — no hero, no three-column feature grid. **Dense, honest** tool.  
2. **Confidence visible** — every row shows **tier** (`unknown` / `low` / `medium` / `high`) without **scary red** unless `evidence[]` exists (product rule).  
3. **Calm copy** — prefer “**We’re not sure yet**” over “**Critical vulnerability**” when data is thin.  
4. **Subtraction** — one primary screen for M1; settings stay **minimal**.

---

## Pass 1 — Information architecture (8/10)

**Order of attention (top → bottom):**

1. **Page title + status strip** — “Lanternis” + connection to **127.0.0.1** + **scan state** (Idle / Scanning / Paused error).  
2. **Primary actions** — `[Start scan]` `[Cancel]` (Cancel disabled when idle).  
3. **Scan progress** — progress bar or **“42 / 254 hosts · polite mode”** + **phase label** (ping batch N).  
4. **Device table** — sortable columns: **IP**, **Reachability**, **Label**, **Confidence**, **Last seen**, **Next step** (link or hint).  
5. **Footer / trust** — one line: “**Only scanning your configured network.**” + link to **plain-language** data note (modal or `/about`).

**ASCII shell:**

```
+------------------------------------------------------------------+
| Lanternis · 127.0.0.1:PORT          Scan: Idle | Last: --:--     |
+------------------------------------------------------------------+
| [ Start scan ]  [ Cancel ]     Mode: [ Normal v ]                 |
| ████████░░░░░░░░  168/254   Phase: ICMP batch 12                |
+------------------------------------------------------------------+
| IP           Reach   Label        Conf.    Next step            |
| 192.168.1.1  yes     Unknown      unknown  Add hint…            |
| ...                                                               |
+------------------------------------------------------------------+
| Only scans 192.168.1.0/24 · Data stays on this computer          |
+------------------------------------------------------------------+
```

**Constraint worship:** If only **three** columns fit on **narrow** view, keep **IP**, **Reachability**, **Confidence**; **Label** + **Next** collapse to **detail drawer** or expandable row.

---

## Pass 2 — Interaction state coverage (9/10)

| Feature | LOADING | EMPTY | ERROR | SUCCESS | PARTIAL |
|---------|---------|-------|-------|---------|---------|
| **Device table** | Skeleton rows or “Loading last scan…” | Illustration + “**No scan yet**” + **Start scan** CTA | “Couldn’t read database” + **Retry** | Table populated | “**12 hosts, 3 uncertain**” banner |
| **Start scan** | Button **spinner**, disable double-submit | N/A | “**Permission denied**” + **help link** (OS-specific) | Progress region appears | Scan ends with **warnings** (some batches skipped) |
| **Cancel** | — | Disabled | “**Cancel failed**” toast | Returns to **Idle** with **partial** results kept | — |
| **Intel cell** (C1+) | Spinner per row | “—” | “**Intel offline**” / rate limit message | CVE/OSV **badges** with **link** | “**Stale** · last checked Tue” |

**Empty state copy (warmth):** “**Nothing here yet.** Run a first scan—we’ll list what responds and be honest about what we can’t name.”

---

## Pass 3 — User journey & emotional arc (8/10)

| Step | User does | User should feel | Plan supports |
|------|-----------|------------------|---------------|
| 1 | Opens `http://127.0.0.1:…` | “**This is local, not the cloud**” | Title, bind address visible, short trust line |
| 2 | Starts scan | “**In control**—I can cancel” | Cancel, progress, polite mode label |
| 3 | Sees many **Unknown** | “**Not stupid—just unknown**” | Confidence column + calm copy |
| 4 | Hits error | “**I know what failed**” | Specific errors, no raw stack in UI |
| 5 | (Later) Intel row | “**Prove it**” | Evidence links, no orphan severity |

---

## Pass 4 — AI slop risk (9/10)

**Banned for v0:** generic **SaaS card grid**, **Inter + purple gradient**, **stock hero**, **“AI-powered”** badge soup.

**Instead:**

- **Typography:** system UI stack — `ui-sans-serif, system-ui, sans-serif`.  
- **Color:** **light** default — background `#f8f9fa`, surface `#fff`, text `#1a1a1a`, border `#dee2e6`, **accent** one hue only **e.g.** `#0d6efd` for links/actions; **no** gradient backgrounds.  
- **Shape:** **4px** radius, **1px** borders—feels like a **tool**, not a **pitch deck**.  
- **Density:** table **row height ≥ 40px**; comfortable for **mouse**; touch targets for primary buttons **≥ 44px**.

---

## Pass 5 — Design system alignment (5/10 → documented)**

**No `DESIGN.md`.** v0 tokens (embed in CSS or `<style>`):

```css
:root {
  --ln-bg: #f8f9fa;
  --ln-surface: #ffffff;
  --ln-text: #1a1a1a;
  --ln-muted: #6c757d;
  --ln-border: #dee2e6;
  --ln-accent: #0d6efd;
  --ln-warn-bg: #fff3cd;
  --ln-danger-text: #842029; /* use ONLY with evidence */
}
```

**Promoted:** **`DESIGN.md`** at repo root (see **`/design-consultation`**, 2026-03-28); preview: **`docs/design-preview.html`**.

---

## Pass 6 — Responsive & accessibility (8/10)

- **Landmarks:** `<main>`, `<header>`, `table` with `<caption class="sr-only">` or visible “Devices on your network.”  
- **Keyboard:** **Tab** through **Start** → **Cancel** → **Mode** → table **focus** (row focus ring); **Enter** starts scan when focus on button.  
- **Screen reader:** announce **scan state changes** via **`aria-live="polite"`** on status region.  
- **Contrast:** body text vs background **≥ 4.5:1**; links not **color-only** (underline on hover).  
- **Mobile:** **320px** width — horizontal scroll for table **allowed** with sticky first column **IP**; primary actions **stack** vertically.

---

## Pass 7 — Resolved vs deferred decisions

| Decision | Resolution |
|----------|-------------|
| **Table vs cards** | **Table** for M1 (scanability). |
| **Scan mode UI** | **Select** Normal / Light / Thorough (copy explains **politeness**). |
| **Dark mode** | **DEFER** — not in v0 (`prefers-color-scheme` optional in P3). |
| **i18n** | **DEFER** — English only v0. |
| **Logo** | **Wordmark** “Lanternis” text only v0. |

---

## NOT in scope (design)

- Marketing website, onboarding **wizard** (deferred per CEO/TODOS).  
- **Remote** access UI.  
- **Custom illustration** set.

---

## Implementation handoff

- **HTML:** semantic table + minimal JS for **poll** scan status **or** SSE later.  
- **CSRF:** mutating fetches include token per **ENGINEERING-PLAN**.  
- **After ship:** run **`/design-review`** on **live** localhost for pixel QA.

---

## Design review scores (summary)

| Pass | Before | After (this doc) |
|------|--------|-------------------|
| IA | 3 | 8 |
| States | 2 | 9 |
| Journey | 3 | 8 |
| Anti-slop | 4 | 9 |
| Design sys | 2 | 5 (tokens only) |
| A11y / responsive | 3 | 8 |
| Decisions | — | 4 resolved, 3 deferred |

**Overall:** **4/10 → 8.5/10** for plan completeness.

---

## Plan reconciliation — shipped UI vs this doc (post-2026-03)

The following shipped **after** the original IA sketch; this section keeps the plan honest for future design reviews.

| Area | Original plan | Shipped today |
|------|----------------|---------------|
| **Table columns** | IP, Reach, Label, Conf., Last seen, “Next step” | **Next step** not present; added **Open ports** (probe list hits), **Hints** (passive ARP/mDNS/SSDP), **Hide unknown reachability** filter |
| **Scan progress** | “ICMP batch” style | Phase is **probe**; copy reflects **TCP vs ICMP** (`/api/runtime`, probe banner) |
| **Trust / diagnostics** | Footer + “data note” | **First-run overlay**, **`/about`** with full diagnostics JSON + **redacted support bundle** download (`POST /api/support/export`) |
| **Modes** | Normal / Light / Thorough | Same control; copy ties mode to **parallel workers + TCP port breadth** |

**Gap vs plan:** “Next step” column / drawer remains **unimplemented** — either add to TODOS as explicit backlog or formally **defer** under NOT in scope.

---

## P3 — Scan history & diff (design spec — draft for implementation)

**Intent:** User sees **what changed** between scans (new/removed/changed hosts), without pretending full forensics.

### Information architecture

1. **Default:** keep **one primary screen** (device table). History is **secondary**: a **panel**, **modal**, or **`/history`** route — pick one in eng review; default recommendation: **collapsible panel** below scan controls so localhost stays single-page.
2. **Summary strip:** one line after a scan completes, e.g. “**Last scan:** +2 hosts · −1 host · 3 labels changed” with **Details** affordance.
3. **Detail view:** table or list of **diff rows** (IP, change type: added/removed/changed, optional label delta). No raw packet dumps.

### Interaction states

| Feature | LOADING | EMPTY | ERROR | SUCCESS | PARTIAL |
|---------|---------|-------|-------|---------|---------|
| **History summary** | Skeleton or “Comparing…” | “No prior scan to compare” + run scan CTA | “Couldn’t load history” + Retry | Diff summary visible | “Partial: scan cancelled” |

### User journey (emotional)

| Step | User feels | Plan supports |
|------|------------|---------------|
| Sees diff summary | “I’m not crazy — the network really changed” | Plain counts, no alarmist styling |
| Opens details | “I can act on this” | Per-IP rows, calm copy |

### NOT in scope (P3 history)

- Multi-user shared history, cloud sync  
- Diff of **raw** passive hint payloads (summaries only)  
- Legal “proof” — this is **inventory aid**, not evidence chain of custody  

---

## P3 — New open-port alerts (design spec — draft)

**Intent:** When **`open_ports`** gains ports vs **previous scan snapshot**, the user **notices** without email/push.

### Information architecture

1. **Banner (recommended):** **`aria-live="polite"`** region below status strip: “**New open ports** on 2 host(s) since last scan” + **Review** → scroll/focus table or open filter.  
2. **Row-level:** subtle **badge** on IP or Open ports cell (“New”) — only if it does not clutter dense table; **constraint worship:** pick **banner OR badges**, not both for v1.

### Interaction states

| Feature | LOADING | EMPTY | ERROR | SUCCESS |
|---------|---------|-------|-------|---------|
| **Port diff** | — | No prior snapshot → no banner | Failed to read last snapshot | Banner + optional row hints |

### Unresolved decisions (pick before build)

| Decision | Resolution / notes |
|----------|-------------------|
| **Snapshot granularity** | Eng review: prefer **normalized per-scan rows** (see `UI-PLAN` GSTACK eng notes); still lock schema in implementation. |
| **Dismiss behavior** | **CEO cherry-pick #2 (2026-03-28):** **v1 = dismiss until next scan** (clears when a new scan completes; no persistent snooze). **24h snooze** → deferred (see `TODOS.md` if promoted later). |
| **ICMP** | `icmp` token in `open_ports` vs TCP-only diffs — copy must explain parity; diff logic treats `"icmp"` as a first-class token. |

### NOT in scope (P3 port alerts)

- OS notifications, email, webhooks  
- Port **scanning** beyond existing probe list  

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | **RECORDED** | SELECTIVE EXPANSION recommended; Approach A (normalized snapshots); cherry-picks table; landscape note |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | **ISSUES_OPEN** | 10 issues, 1 critical gap (scan/db ordering); P3 needs snapshot storage + tests |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | **RECORDED (FULL)** | score 6→8/10; P3 IA drafted |

- **UNRESOLVED:** snapshot storage shape; snapshot timing vs passive merge; **Approach A vs B** (CEO recommends A). **Cherry-picks:** CIDR + export + dismiss v1 **per `TODOS.md` / P3 port alerts**; timeline + metrics **deferred**.
- **VERDICT:** **Trust product** = durable diff + no false “new port” theater — **fix orphan-scan before P3**; **re-run `/plan-eng-review`** after scope lock; **`/plan-design-review`** after P3 UI.

### CEO strategic review (2026-03-28, commit `e316605`)

**Mode (0F):** Default **`SELECTIVE EXPANSION`** — baseline = P3 from `TODOS.md` + `UI-PLAN`; optional cherry-picks listed in `~/.gstack/projects/home-scanner/ceo-plans/2026-03-28-p3-scan-history-port-alerts.md`. **HOLD SCOPE** if you want zero scope discussion; **SCOPE REDUCTION** if you only want the reliability fix first.

**0A Premise:** Without **change-over-time**, Lanternis competes on **honesty** alone; diff/history is the **smallest strategic lake** that supports “**what changed on my LAN?**” vs cloud scanners (Fing-class scale + alerts).

**0C-bis:** **Approach A** (normalized snapshots + retention) is the **complete** option; **B** acceptable if tested; **C** (session-only diff) **rejected** — breaks trust after reload.

**Cherry-picks (2026-03-28):** Following CEO recommendations — **#5 CIDR** + **#1 export** on P3 track; **#2 dismiss** locked in P3 port alerts (**dismiss until next scan** v1); **#3 timeline** + **#4 metrics** deferred (`TODOS.md`).

**Sections 1–11 (condensed):** **Architecture** — snapshots at scan boundary; **Errors** — orphan scan = **CRITICAL GAP**; **Security** — new read APIs stay localhost-bound, no new CSRF on GET; **UX** — banner OR badges (design doc); **Tests** — diff + cancel + DB fail; **Observability** — structured logs on snapshot write; **Deploy** — SQLite migration backward-compatible; **12-month** — snapshot layer enables future audit exports without rework.

### Engineering review notes (2026-03-28, commit `e316605`)

**Plan target:** P3 from `TODOS.md` — **scan diff/history** and **new open-port alerts**, building on `hosts.open_ports_json` and `scan_runs`.

**What already exists**

| Piece | Role | Reuse for P3 |
|-------|------|----------------|
| `scan_runs` | Timestamps, mode, cancel flag | Correlate **completed** runs; needs **snapshot** child data or FK linkage |
| `hosts` | Live upsert during + after probe | **Not** a historical truth — only **latest** row per IP |
| `LastScanRun` / `audit` | Last run + `scan_finished` events | Good hooks for “when to snapshot”; audit is not a substitute for structured diff |
| `UpsertHost` | Streaming updates | Diff must use **immutable snapshot at scan boundary**, not live table mid-flight |

**NOT in scope (engineering)**

- Cloud sync, multi-device history  
- Storing full raw passive payloads in snapshot tables (summaries only; aligns with design NOT in scope)  
- Replacing SQLite with another store for v1 of this feature  

**ASCII — intended data flow (P3)**

```
[POST /scan/start] --> InsertScanRun? --> Scanner.Start --> ... probes --> UpsertHost (live)
                              |
                              v
              watchAndFinalize(dbRunID) --> MarkScanEnded
                              |
                              v
              NEW: PersistSnapshot(dbRunID)  <-- compare N vs N-1 for diff + port alerts
                              |
                              v
              GET /api/scan/diff (or similar) --> UI banner + history panel
```

**Step 0 — scope & risk**

1. **No existing snapshot** — P3 is a **data model extension**, not a thin UI tweak. Minimum complete lake: **persist per-scan inventory** (or diff summary + drill-down), **retention** (last N runs or TTL), **tests** for diff and migrations.  
2. **Orphan-scan bug (critical):** `scanner.Start` runs **before** `InsertScanRun`. If `InsertScanRun` fails, the probe **still runs** but `watchAndFinalize` is never started — **no** `MarkScanEnded`, **no** audit coupling, **no** future snapshot hook. **Fix:** create DB row first *or* `Cancel()` the scanner and surface error (minimal diff, high value).  
3. **Snapshot timing:** Passive ARP/SSDP/mDNS merges **after** active probe finishes. Decide explicitly: snapshot **after** passive work visible in `watchAndFinalize` (recommended for user-visible “what changed”), vs active-only (simpler, mismatches table for minutes).  
4. **Inventory scope:** `hosts` can contain IPs **outside** the current CIDR from older scans. Diff must define **CIDR-filtered** vs **global** — document in API and tests.

**Opinionated recommendations (Lake-preferring)**

| # | Topic | Recommendation | Maps to |
|---|--------|----------------|---------|
| 1 | Orphan scan | **InsertScanRun before Start**, or on Insert failure call **`scanner.Cancel()`** + return 500 | explicit > clever; failure modes |
| 2 | Storage | **New table** `scan_host_snapshots` (scan_id, ip, reachability, open_ports_json, label, …) + index on scan_id — avoids huge JSON blobs and keeps SQL testable | well-tested; minimal magic |
| 3 | Retention | **DELETE** snapshots older than last **10** runs or **30 days** in same migration path as insert | blast radius; disk |
| 4 | API | **`GET /api/scan/diff?since_id=`** or `last vs previous` — read-only, no CSRF | ENGINEERING-PLAN patterns |
| 5 | Tests | **Store:** migration + snapshot + diff pure functions; **HTTP:** diff JSON shape; **regression:** InsertScanRun failure path | non-negotiable tests |

**Test diagram (P3 additions)**

```
                    +------------------+
                    |  MarkScanEnded   |
                    +--------+---------+
                             |
              +--------------v---------------+
              | PersistSnapshot(scan_id)      |  NEW
              | (read hosts or in-memory      |
              |  buffer — decide in impl)      |
              +--------------+---------------+
                             |
              +--------------v---------------+
              | Diff(scan_id, scan_id-1)       |  NEW
              +--------------+---------------+
                             |
         +---------+---------+---------+
         |         |                   |
    +----v----+ +--v---+          +-----v-----+
    | Banner  | | API |          | Unit tests |
    | (ports) | |JSON |          | + store    |
    +---------+ +-----+          +-----------+
```

**Failure modes (P3)**

| Failure | Test? | Handling | User-visible |
|---------|-------|----------|--------------|
| InsertScanRun fails after Start | **missing** | **critical gap** — silent orphan scan | stuck “scanning” / inconsistent |
| Snapshot partial (cancelled) | TBD | Skip diff or mark partial | banner off |
| DB full on snapshot | TBD | Log + skip snapshot | degrade gracefully |

**Codex:** CLI not available — skipped.

**Next reviews:** After implementing P3 storage + ordering fix, run **`/plan-design-review`** if UI changes; then **`/ship`** when tests green.
