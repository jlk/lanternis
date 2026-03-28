# Design System — Lanternis

## Product context

- **What this is:** A **localhost-first** console for home LAN discovery and honest device inventory—dense table, scan controls, trust copy. No cloud UI.
- **Who it's for:** The household “IT person” who wants clarity without security theater.
- **Space / industry:** Network inventory / discovery tools (peers: Fing-class products—but we stay **local**, **calm**, **utility-shaped**).
- **Project type:** Internal tool / single-page **dashboard** (embedded HTML in Go, not a SPA framework).

## Aesthetic direction

- **Direction:** **Industrial / utilitarian** — function-first, paperwork-on-a-desk, not a marketing site.
- **Decoration level:** **Minimal** — typography, 1px borders, and spacing do the work; no gradients, no hero, no icon-in-circle feature grids.
- **Mood:** Competent, quiet, honest. Users should feel **in control** and **not sold to**.
- **Reference:** Product principles live in `docs/UI-PLAN.md`; this file is the **token + implementation** source of truth.

## Typography

- **Stack (shipping UI):** `ui-sans-serif, system-ui, sans-serif` — **no webfont loading** in the embedded console (zero deps, fast load, trustworthy on localhost).
- **Display / hero:** Same as body (there is no marketing hero in the console).
- **Body / UI labels:** System stack, **14px** base for table and controls; **13px** for captions and secondary metadata.
- **Data / tables:** Same stack; use **`font-variant-numeric: tabular-nums`** on IP and numeric columns so columns align.
- **Code / diagnostics:** `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace` for JSON or raw snippets only (e.g. `/about`).
- **Loading:** N/A for console (system fonts only).
- **Scale:** `12px` (meta) · `13px` (caption, footer) · `14px` (body, table) · `16px` (section titles) · `20–22px` (page title `h1`).

## Color

- **Approach:** **Restrained** — one accent hue; neutrals carry the UI; semantic colors only where meaning exists (warning, danger-with-evidence).

### Light (default)

| Token | Hex | Usage |
|-------|-----|--------|
| `--ln-bg` | `#f8f9fa` | Page background |
| `--ln-surface` | `#ffffff` | Panels, table background |
| `--ln-text` | `#1a1a1a` | Primary text |
| `--ln-muted` | `#6c757d` | Secondary labels, hints |
| `--ln-border` | `#dee2e6` | Borders, dividers |
| `--ln-accent` | `#0d6efd` | Primary buttons, links, focus ring |
| `--ln-warn-bg` | `#fff3cd` | Banners, non-destructive warnings |
| `--ln-warn-border` | `#ffe69c` | Warning outline |
| `--ln-danger-text` | `#842029` | **Only** with verified evidence (product rule) |

### Dark (`prefers-color-scheme: dark` or `[data-theme="dark"]`)

- Reduce contrast slightly: backgrounds **not** pure black; text **not** pure white.
- Saturation ~10–15% lower on accent for comfort.

| Token | Hex | Usage |
|-------|-----|--------|
| `--ln-bg` | `#121416` | Page |
| `--ln-surface` | `#1a1d21` | Panels / table |
| `--ln-text` | `#e8eaed` | Primary |
| `--ln-muted` | `#9aa0a6` | Muted |
| `--ln-border` | `#3c4043` | Borders |
| `--ln-accent` | `#5c9eff` | Accent (desaturated vs light) |
| `--ln-warn-bg` | `#3d3200` | Warning surface |
| `--ln-warn-border` | `#6b5a00` | Warning border |
| `--ln-danger-text` | `#f4a4a9` | With evidence only |

### Semantic

- **Success:** optional `#198754` (use sparingly; most states are neutral).
- **Info:** same as `--ln-accent` or a slightly muted blue for inline banners.

## Spacing

- **Base unit:** **4px**
- **Density:** **Comfortable** — table rows **≥ 40px** tall; primary actions **≥ 44px** touch height.
- **Scale:** `4px` · `8px` · `12px` · `16px` · `24px` · `32px` (use **8px** multiples for layout rhythm).

## Layout

- **Approach:** **Grid-disciplined** — single column main, max width **1080px**, consistent padding **16px**.
- **Grid:** One primary column; table **horizontal scroll** allowed below **320px** with **sticky first column (IP)** when implemented.
- **Max content width:** `1080px`
- **Border radius:** **4px** on panels, inputs, buttons; **full** only for pills/chips if introduced later.

## Motion

- **Approach:** **Minimal-functional** — only transitions that aid comprehension (e.g. scan status updates).
- **Easing:** `ease-out` for enter, `ease-in` for exit.
- **Duration:** **100–200ms** for UI feedback; no choreographed marketing motion.

## Accessibility

- **Contrast:** Body text vs background **≥ 4.5:1** (light and dark).
- **Focus:** Visible focus ring on interactive controls (use accent or outline).
- **Live regions:** `aria-live="polite"` for scan status and non-destructive alerts (see `UI-PLAN`).
- **Landmarks:** `<main>`, `<header>`; table has caption or `sr-only` title.

## Anti-patterns (do not ship)

- Purple/violet **gradients** as default chrome
- **Inter / Roboto** as primary if webfonts are ever added without explicit opt-in
- Three-column **feature grid** with icons in circles for this product
- **Scary red** for “unknown” or thin data (use calm copy; red only with evidence)

## Relationship to code

- Embedded styles in `internal/httpserver/server.go` (and related) should **mirror these tokens** (`--ln-*`). When adding UI, **extend tokens here first**, then copy to embedded CSS.
- **`docs/UI-PLAN.md`** remains the **IA, states, and copy** spec; **`DESIGN.md`** is the **visual contract**.

## Decisions log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-03-28 | Initial `DESIGN.md` from `/design-consultation` | Codifies `UI-PLAN` v0 tokens; adds dark palette + spacing/motion for implementation |
| 2026-03-28 | System fonts only for console | Localhost tool: no CDN dependency, no FOUT, matches honesty positioning |
| 2026-03-28 | **Ship it** — Q-final **A** (`/design-consultation`) | Baseline system accepted; iterate in `DESIGN.md` before changing embedded CSS |
