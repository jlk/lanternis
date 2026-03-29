# Lanternis — agent notes

## Persona

Adopt the mindset of a **network security expert**: think in terms of **attack surface**, **exposure**, **trust boundaries**, **evidence quality**, and **what is safe to claim** (e.g. CVE eligibility requires versioned software identity, not OUI-only guesses). Prefer **honest uncertainty** over inflated confidence. When suggesting features or copy, align with **vulnerability scanning** end goals (see **`docs/VULN-SCANNER-PLAN.md`**) as well as home-LAN usability.

## Design system

Always read **`DESIGN.md`** before making any visual or UI decisions in this repo.

All font choices, colors, spacing, motion, and aesthetic direction for the localhost console are defined there. **`docs/UI-PLAN.md`** covers information architecture, interaction states, and copy.

Do not deviate from `DESIGN.md` without explicit user approval. In QA mode, flag any UI code that does not match `DESIGN.md` or `UI-PLAN.md`.

## Product scope (fingerprinting)

- **IoT-first** inventory: prioritize honest signals for cameras, hubs, speakers, and appliances; a little Windows on the LAN is incidental.
- **SNMP:** **not implemented** — consumer devices rarely expose useful SNMP; it is mainly an **enterprise** gear signal (`sysDescr`). Lanternis targets **consumer / home** LANs first, so SNMP is out of scope unless product direction explicitly adds an enterprise-oriented profile later.
- **SMB:** no deeper SMB2+ work until basic IoT-oriented fingerprinting and tiered OS fusion are solid; minimal anonymous SMB strings may remain. Deeper SMB matters more for **Windows-heavy** vuln coverage later.
- Scan mode **`deep`** = same TCP port breadth as **`thorough`**, longer per-host budgets, optional raw TCP stack fingerprint on Linux (elevated privileges); not for everyday use.

**Vulnerability scanner direction:** **`docs/VULN-SCANNER-PLAN.md`** — findings (vendor/product/version per surface), CPE mapping, then NVD/OSV.
