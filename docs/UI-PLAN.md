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

**Optional later:** `/design-consultation` → promote to **`DESIGN.md`**.

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
