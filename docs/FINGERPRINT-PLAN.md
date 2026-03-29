# Fingerprint plan — Lanternis

**Status:** living doc · **Last updated:** 2026-03-28

This document is the **product + engineering** plan for turning discovered IPs into **meaningful device identities**—not just a list of techniques. It is scoped to a **single-binary, localhost-first, honest-inventory** tool.

**Primary outcome (locked for this effort):** **L4 — product or model hints** (see §1.2). Implementation should be judged against whether we can extract **manufacturer / model / firmware-ish strings** with provenance—not just L2 “camera” or L3 “Chromecast-like.”

---

## 1. Vision: from addresses to “what is this?”

### 1.1 North star

**Goal:** For every host Lanternis discovers, the user can answer—not always instantly, but **reliably over time**—**what that device is**: role on the network, vendor, and—where evidence allows—**product model or firmware-class facts** (**L4**), with **citations** (which protocol, which field, which scan) so nothing feels invented.

That is different from “we run three heuristics.” The through-line is an **identity record per host** that **deepens** as evidence accumulates: passive discovery, active probes, optional capture, optional user confirmation, and eventually **intel** (CVE posture) when the record is specific enough.

Lanternis should feel like **building a labeled map of your LAN**, not a one-shot guess.

### 1.2 The identity ladder (levels of “knowing”)

No serious tool promises perfect automatic naming for every cheap IoT widget. What *is* achievable is a **ladder**: each rung is a narrower hypothesis, backed by stronger or more diverse evidence.


| Level                           | What the user gets                                                                             | Typical signals                                                                                                                 |
| ------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **L0 — Presence**               | “Something responded at this IP.”                                                              | ICMP/TCP probe, ARP row                                                                                                         |
| **L1 — NIC vendor**             | “The network interface is probably from **vendor X**.”                                         | IEEE MA-L/M/M-S lookup from MAC                                                                                                 |
| **L2 — Role / class**           | “This behaves like a **camera**, **speaker**, **printer**, **router**, **hub**, …”             | SSDP `ST` / device type, mDNS service types (`_hap`, `_googlecast`, `_ipp`), DHCP class (if seen)                               |
| **L3 — Ecosystem / family**     | “Likely **Chromecast / Google TV stack**, **HomeKit**, **Alexa-class**, …”                     | mDNS names + service combos, SSDP `SERVER`, HTTP `Server`, TLS ALPN/SNI patterns                                                |
| **L4 — Product or model hints** | “**Manufacturer model string**, firmware-ish version, or hostname that encodes serial prefix.” | UPnP **device description XML** from `LOCATION`, HTTP `<title>`, SSH banner, TLS cert subject (**SNMP is out of scope for this project** — see §6) |
| **L5 — Ground truth label**     | “**Living room TV**” or “**kid’s laptop**”—truth for *this* home.                              | **User-edited name**, pinned to MAC/IP history                                                                                  |
| **L6 — Posture (intel)**        | “Known vulns for **this software version**” (when L4 gives CPE-like facts).                    | **NVD / OSV** using stored API keys; **never** the primary name source                                                          |


**Visionary but honest:** most homes will land many devices at **L2–L3** without heroic effort. **L4** is the stretch goal for “what device is this?” in the **product** sense; it requires **richer protocol surfaces** (UPnP description, HTTPS to LAN devices) and **merge logic** (tiered / fusion-style) that does not collapse uncertainty. **Primary target:** consumer **IoT** and appliances; a little Windows on the LAN is incidental. **SMB:** only minimal anonymous probes for now—no SMB2+ expansion until basics are solid.

The plan below is how we **climb the ladder in software**—and where **humans** stay in the loop when automation plateaus.

### 1.3 Convergence over time (why identity is a process, not one scan)

“Knowing” improves because:

- **Repeated scans** refresh ports and hints; **diff across snapshots** shows stable vs flaky signals (trust stable SSDP over one-off noise).
- **Confidence** should **increase** when independent signal families agree (OUI printer vendor + IPP mDNS + port 631).
- **Contradictions** surface explicitly (“OUI says Intel; SSDP says TV”—show both, don’t pick silently).

This is the same intuition as **NAC and analytics** products: identity is often **Bayesian fusion** over observations, not a single packet.

### 1.4 Evidence graph (conceptual model)

Per host, treat identity as a small **evidence graph** (implemented as structured `fingerprint_blob` + `raw_hints_json`):

- **Nodes:** observations (MAC, SSDP fields, mDNS records, banner lines, TLS features).
- **Edges:** “supports hypothesis H” with weight and provenance.
- **Output:** best **summary label** + **alternates** + **confidence**—never a black box; UI can always drill to “why we think this.”

That model scales from **deterministic rules today** to **learned weights tomorrow** without throwing away trust.

### 1.5 Human-in-the-loop as first-class

For **L5**, the product should embrace **user confirmation**: rename, “this is the same device as last week,” merge duplicates. That path is how every home admin actually finishes the job—and it gives Lanternis **ground truth** for improving heuristics and for **diff alerts** (“this IP now claims to be a different device class”).

### 1.6 L4 definition of done (what we ship toward)

An identity record reaches **L4** when it contains at least one **structured product fact** with citation, for example:

| Field (examples) | Typical source |
|------------------|----------------|
| `manufacturer` / `model_name` / `model_number` | UPnP device description (`friendlyName`, `modelName`, `manufacturer`), HTTP landing page text |
| `software_version` / `firmware_version` | UPnP `device`/`service` fields, SSH banner, HTTP `Server` + body, TLS cert O/OU if present |
| `serial` or serial-like | UPnP XML, rare HTTP admin pages (careful with PII—prefer model over serial in UI) |

**UI expectation:** show a **primary line** like `Manufacturer Model (fw x.y)` when available, plus **“Evidence”** linking to the exact field (e.g. “UPnP `modelName`”, “TLS cert CN”).

**Not L4:** OUI-only vendor, or “MediaRenderer” from SSDP `ST` without a **model string**—that stays **L2** unless merged with another signal that carries a product name.

---

## 2. Phased roadmap (L4-first)

Phases are ordered so **L4-capable paths** land **early**: UPnP description parsing is not an afterthought—it is the **cheapest high-yield** source for consumer gear. Active HTTP/TLS/SSH is **core**, not optional, for NAS/camera/router-class devices.

### Phase 0 — Contract (blocking)

Define **`fingerprint_blob` v1** as the **identity record**, including **L4 slots**: e.g. `manufacturer`, `model`, `firmware_version` (nullable), plus **`signals[]`** with provenance, **`hypotheses[]`**, **`ladder_max`** (highest L0–L4 reached), **`confidence`**, **`updated_at`**. Raw `raw_hints_json` stays **evidence**; fingerprint is **derived**.

**Unlocks:** UI and APIs can render **product line** vs **class-only** without ad-hoc strings.

### Phase 1 — Foundation + first L4 from UPnP

1. **MAC → vendor (IEEE MA-L/M/S)** → **L1** (and corroboration for L4 merges).
2. **SSDP** — parse `ST`, `SERVER`; **fetch `LOCATION` device description XML** (timeout, size cap, same politeness as scan) and extract **manufacturer / model / friendlyName / serial** where present → **primary L4 path** for TVs, streamers, many IoT bridges.
3. **mDNS** — service types + TXT/name patterns → **L2–L3**; **L4** only when TXT or host strings carry **model-like** tokens (document heuristics).

**Exit:** **three independent** contributors; at least one must **emit L4 fields** when UPnP `LOCATION` is valid—meets “3+ before plugins” gate.

### Phase 2 — Merge, stability, diff (L4-aware)

- Prefer **L4 facts** over L2 labels when populating **primary summary**; keep **class** as a secondary facet.
- **Stability:** model strings should not flicker—use last-seen agreement or stable XML fields.
- **Snapshot diff:** highlight **model/firmware changes** between scans (security-relevant).

**Unlocks:** trustworthy **product line** when data exists.

### Phase 3 — Active app-layer probes (L4 backbone for non-UPnP gear)

**Required for L4 on many networks**—cameras, NAS, routers often expose **no** useful UPnP model string.

| Probe | L4 payoff |
|-------|-----------|
| **HTTP(S)** GET/HEAD to open 80/443 | `<title>`, meta tags, JSON `model` fields on admin UIs, `Server` header |
| **TLS** client to device | Cert **subject/issuer**, SAN; optional **JA4S** fingerprint for software class |
| **SSH** banner on 22 | OpenSSH version, vendor-branded banners |
| **SNMP** | **Not planned** — excluded by product decision (see §6). |

**Policy:** same **rate limits / modes** as scan kindness; **HTTPS** may use **insecure skip verify** only to read cert—**never** send creds.

### Phase 4 — Observation plane (fills L2–L3, sometimes L4)

- **DHCP** / **pcap** — **OS class** and occasionally **host name** strings; **secondary** to Phase 3 for **model** strings.

### Phase 5 — Pluggable packs + optional ML

- **`FingerprintProvider`** + **JSON packs** (regexes for vendor admin pages, mDNS TXT quirks).
- **ML** only as **experimental** enrichment on top of extracted strings.

### Phase 6 — Intel (L6)

- **NVD / OSV** when **L4** fields support **CPE** or version search—downstream of **L4**, not a substitute.

---

## 3. State of the art (research + industry)

### 3.1 Axes of approach


| Axis                     | Notes                                                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Passive vs active**    | Passive discovery and sniffing dominate IoT research; active probes improve **L3–L4** at the cost of intrusiveness.                |
| **Static vs behavioral** | Static: MAC, DHCP options, SSDP, mDNS, banners, TLS. Behavioral ML on flows can raise accuracy but adds ops and privacy tradeoffs. |
| **Deterministic vs ML**  | Ship **rules + registries** first; ML/LLM as optional layers—not sole authority.                                                   |


### 3.2 Layered signals (reference)

- **MAC / IEEE** — MA-L, MA-M, MA-S CSVs → **L1** (corroboration for L4).
- **TCP/IP** — p0f (passive), Nmap (active) → **L2–L3** OS family; rarely **L4** alone.
- **TLS** — Cert fields → **L4** when O/CN/SAN carry product or org; JA4S → **L3** class.
- **SSDP/UPnP** — `**LOCATION` device XML** → **primary L4** path for many consumer devices; bare `ST` → **L2** only.
- **mDNS** — service types → **L2–L3**; TXT/hostnames → sometimes **L4**.
- **HTTP/S, SSH** — **L4** when banners/pages expose model/firmware.
- **SNMP** — **out of scope** for Lanternis (not implemented; not on the roadmap).
- **DHCP** — option vectors → mostly **L2**; occasional hostname hints.

### 3.3 Practice takeaways

- Combine **orthogonal** signals; show **evidence**.
- Calibrate **confidence**; fingerprints are usually **heuristic**, not cryptographic identity.
- **Ethics:** rate limits, disclosure, alignment with authorized-scan UX.

---

## 4. Current repo reality (baseline)

- **Stored:** `raw_hints_json` (ARP MAC, SSDP `st_types`/`server`/`location`, mDNS **names + service types/TXT**), **open_ports**, and a structured **`fingerprint_blob`** JSON record.
- **Fingerprint pass (post-scan):** derives `manufacturer/model/serial` (UPnP XML), vendor (OUI or manufacturer), **reverse DNS (PTR)** names, HTTP(S) title + **Server** headers (generic servers do **not** imply OS family), TLS cert names, SSH banner, optional **raw TCP SYN/SYN+ACK** features in **`deep`** scan mode on Linux only, plus a heuristic **`device_class`** (“kind”) fused from ports + SSDP + mDNS + PTR + web banners. **OS inference** uses **tiered fusion** (strong banners vs weak stack text).
- **UI:** host list shows **Vendor** and **Kind**; per-host detail shows the **evidence chain** and per-scan snapshot history.
- **Rule:** still defer **pluggable packs** until **3+** heuristics prove merge shape (`TODOS.md`).

---

## 5. Testing and CI strategy

- **Golden fixtures** for `raw_hints` + ports → expected **identity record**—no live LAN in CI.
- **Trimmed** IEEE CSV in testdata; optional DHCP/SSDP fixtures if capture paths land.

---

## 6. Explicit non-goals (near term)

- **SNMP** — **never** in this project: no UDP 161 probes, no community strings, no `sysDescr` harvesting.
- **RF / PHY** fingerprinting as core.
- **Cloud LLM** as the primary name for a device.
- **Full** Nmap OS DB or **full** JA4+ suite in v1.
- **Silent** aggressive scanning without user understanding.
- **Deep SMB / SMB2+** OS fingerprinting — deferred until IoT-oriented **basics** (honest HTTP/SSDP/mDNS/TCP fusion, UPnP) are working; current code may keep a minimal anonymous SMB1-style string when available.

---

## 7. References (pointers)

IEEE MA registries; Nmap OS detection; p0f; FoxIO JA4+; UPnP/SSDP; DHCP fingerprinting / Fingerbank-style DBs; IoT fingerprinting surveys (ideas, not default architecture).

---

## 8. Next step in-repo

Implement **Phase 0 + Phase 1**: identity schema + OUI + SSDP/mDNS + merge tests; wire **RecomputeFingerprint** into the scan pipeline; UI that shows **summary + why** (even minimal) so the ladder is visible from day one.