# Vulnerability scanner roadmap — Lanternis

**Status:** concrete plan · **Audience:** implementers + agents  
**North star:** A **vulnerability-oriented** scanner requires **vendor / product / version** (ideally CPE-shaped) per **exposed surface**, not just host-level guesses.

This doc ties **inventory + fingerprinting** to a future **intel** layer (NVD / OSV / ecosystem DBs). It does not replace `docs/FINGERPRINT-PLAN.md` (identity ladder) but **extends** it with a **findings-first** model.

---

## 1. Why this is different from “nice device names”

| Goal | What we optimize |
|------|-------------------|
| **Discovery / UX** | Human-readable labels (PTR, mDNS, UPnP friendlyName) |
| **Vuln scanning** | **Versioned software instances** tied to **ports + protocols**, with **evidence** strong enough to justify CVE lookup |

**OS inference alone** is insufficient for most **consumer IoT**: kernels are opaque; what matters is **firmware**, **embedded web stacks**, **TLS stacks**, **UPnP stacks**, **camera SoC software**. The pipeline must prioritize **extractable versions** over OS family.

---

## 2. SNMP — explicit non-goal (consumer scope)

**Decision:** Do **not** implement SNMP (UDP 161, `sysDescr`, community strings, etc.).

**Rationale:** **Consumer** devices on home LANs **rarely expose or use SNMP** in a way that yields inventory value. SNMP is disproportionately useful for **enterprise** network gear (switches, firewalls, some NAS) where `sysDescr` is a standard L4 signal. Lanternis prioritizes **home / consumer IoT**; the ROI of SNMP code paths, UX, and security review is **low** for that target. If the product later adds an **“enterprise profile”**, SNMP could be revisited as an **optional, opt-in** probe—not a default.

This is **not** a claim that SNMP is bad—only that it is **out of scope** for the current product direction.

---

## 3. Target artifact: normalized “findings” (per surface)

Move from a **single** `fingerprint_blob` per host as the only structured intel to (conceptually):

- **Host** — IP, MAC, reachability, last seen, optional display label.
- **Finding** (many per host) — one row per **actionable software identity** we can attach evidence to.

**Minimum fields (conceptual):**

| Field | Purpose |
|-------|---------|
| `surface` | e.g. `tcp:443/tls`, `tcp:80/http`, `udp:5353/mdns`, `upnp/device` |
| `vendor_guess` | From UPnP, OUI, cert O, Server header, etc. |
| `product_guess` | Model name, server name, app name |
| `version_guess` | Parsed semver or opaque build string |
| `version_confidence` | `high` / `medium` / `low` / `unknown` |
| `evidence_kind` | `upnp_softwareVersion`, `http_json`, `http_header`, `ssh_banner`, `tls_cert`, … |
| `evidence_digest` | Short snippet or hash (no secrets in logs) |
| `cpe_candidate` | Optional later: mapped CPE 2.3 string |
| `vuln_ready` | Bool: safe to query OSV/NVD with this row |

**Rule:** CVE / advisory lookup runs only when `vuln_ready` (or equivalent) is true—**never** invent matches from OUI-only or generic “Linux-like” banners.

---

## 4. Phased implementation (concrete)

### Phase A — Schema + API (no new probes yet)

1. **SQLite / store** tables for `findings` (or JSON array in host row with migration path—prefer separate table for query and diff).
2. **API** — `GET /api/host?ip=` returns `findings[]`; list endpoints can aggregate “hosts with low-confidence versions.”
3. **UI** — Host detail shows **Findings** section: **surface · product · version · confidence · evidence**.

**Exit criteria:** Empty findings list is valid; structure is stable.

### Phase B — Extractors that feed findings (consumer-heavy)

1. **UPnP device description** — Already fetched; **promote** `softwareVersion`, `modelName`, `modelNumber`, `manufacturer` into **findings** with `high` confidence when present.
2. **mDNS TXT** — Parse known keys (`fv`, `version`, `os`, product-specific) into **findings** with **medium** confidence; document per-ecosystem quirks.
3. **HTTP(S)** — Beyond `Server` / `<title>`:
   - Capped GET/HEAD of `/`, common paths (`/version`, `/api/status`, `/cgi-bin/...` only if in curated allowlist).
   - Regex/JSON extractors for `version`, `Firmware`, `build`, semver-like tokens.
   - Store **evidence snippet** (truncated) and **confidence** based on parse quality.
4. **SSH** — Existing banner → **finding** `openssh` + version / distro patch where parseable.
5. **TLS** — Cert O/OU/CN as **weak** product hints; **not** primary version source unless combined with HTTP.

**Exit criteria:** At least one **vuln_ready** finding on a subset of lab devices (UPnP-heavy, NAS, web-admin cameras).

### Phase C — CPE mapping layer (offline)

1. **Vendor/product normalization** — Map strings to **CPE vendor/product** where justified (dictionary + manual overrides).
2. **Version normalization** — Semver cleanup; strip build metadata; reject garbage.
3. **Output** `cpe_candidate` + `mapping_confidence`.

**Exit criteria:** Manual review of 20–30 device types; automated tests on golden strings.

### Phase D — Intel (NVD / OSV)

1. **Query** only when `vuln_ready` and `mapping_confidence` ≥ threshold.
2. **Store** advisory IDs + summary + link; **never** block on cloud if offline.
3. **Diff across scans** — “new CVE for existing CPE” is a first-class alert.

### Phase E — Deeper protocols (as needed for Windows / enterprise)

1. **SMB2+** negotiation / session metadata — **when** SMB scope is expanded (not blocking Phase B–D for IoT).
2. Optional **enterprise profile** — SNMP opt-in, stricter rate limits, separate UX copy.

---

## 5. Alignment with existing code

| Area | Today | Next step |
|------|--------|-----------|
| `internal/fingerprint` | Record + signals, OS tiering | Emit **finding** structs from same probes; reduce emphasis on OS row for vuln story |
| `internal/store` | `fingerprint_blob` on host | Migrate toward **findings** table + host metadata |
| Scan modes | light / normal / thorough / deep | **Deep** remains for raw TCP / heavy HTTP budgets—not for SNMP |

---

## 6. Testing strategy

- **Golden fixtures** — Raw HTTP bodies, UPnP XML, mDNS TXT → expected **findings** + confidence.
- **No live CVE** in CI — mock OSV/NVD responses.
- **Regression** — Version extractors must not regress on truncated / malicious bodies (size caps, no panics).

---

## 7. Open questions (record, don’t block Phase A)

- **Privacy:** Some firmware versions are serial-adjacent; prefer **model + firmware** over **serial** in UI.
- **Rate limits:** HTTP depth must respect per-host budgets and user-visible scan modes.
- **Legal:** Only scan networks the operator owns; copy already in setup flow—reinforce in vuln UI.

---

**Document owner:** product + engineering. Update when Phase A lands or SNMP scope changes.
