# Acquisition Brief â€” Wiretap

**Date:** 2026-09-22  
**Repository:** https://github.com/theworker02/wiretap  
**Default branch:** `main`  
**Primary language:** Go  
**Status:** Diligence briefing only. **No acquisition has occurred** by virtue of this file.  
**License:** Proprietary â€” sale, written commercial license, or completed asset transfer required (see root `LICENSE`).  
**Valuation:** Not stated.  
**Contact:** GitHub [@theworker02](https://github.com/theworker02) Â· [thanks.dev/u/gh/theworker02](https://thanks.dev/u/gh/theworker02)

> Cloning or forking this repository does **not** grant production, redistribution, SaaS, OEM, or commercial rights.

---

## 1. Executive thesis

<img src="assets/logo.svg" alt="Wiretap" width="640"/> **Evidence-backed binary protocol inference Ã¢â‚¬â€ offline, deterministic, explainable** Built by **[@theworker02](https://github.com/theworker02)** Ã¢â‚¬â€ independent tooling for

**Why a buyer cares:** Wiretap packages transferable product IP â€” source, docs, in-repo brand assets, and a diligence room under `docs/acquisition/` â€” under a clear proprietary posture so diligence can proceed without mistaking the repo for open source.

---

## 2. Product snapshot

| Item | Detail |
|------|--------|
| Product | Wiretap |
| Repo | `theworker02/wiretap` |
| Language | Go |
| Open source? | **No** â€” proprietary |
| Rightsholder | theworker02 |
| Diligence pack | `docs/acquisition/` |

### Capability highlights (from current materials)

- [Install](#install)
- [Quick start](#quick-start)
- [What Wiretap does](#what-wiretap-does)
- [CLI](#cli)
- [Projects & workflows](#projects--workflows)
- [Library](#library)
- [Architecture](#architecture)
- [Examples](#examples)
- [Security & privacy](#security--privacy)
- [Docs & site](#docs--site)
- [Contributing](#contributing)
- [License](#license)

---

## 3. Problem / opportunity

Teams evaluating Wiretap typically need either (a) a commercial right to run or embed it, or (b) outright ownership of the Product IP for strategic build-out. Public GitHub visibility without a proprietary license creates false assumptions about free production use. This brief and the linked data room make the commercial path explicit.

---

## 4. What ships today

Honest maturity: treat repository contents, README claims, tests, and release tags as the source of truth. Do not assume production customers, ARR, filed patents, or SLAs unless separately evidenced in diligence.

Typical transferable surfaces:

- Source tree and build/test scripts present in-repo
- Documentation and design notes
- Acquisition / diligence markdown under `docs/acquisition/`
- Branding assets committed to the repository (if any)

---

## 5. Demo / evaluation path (buyer)

Minimal path (no secrets required unless README says otherwise):

```
```
 __        ___ ____  _____ _____  _    ____
 \ \      / (_|  _ \| ____|_   _|/ \  |  _ \
  \ \ /\ / /| | |_) |  _|   | | / _ \ | |_) |
   \ V  V / | |  _ <| |___  | |/ ___ \|  __/
    \_/\_/  |_|_| \_\_____| |_/_/   \_\_|
```
```text
$ wiretap analyze examples/mystery/captures.hex
Wiretap Analysis Report
  length @ 0x04     confidence=High
  checksum trailer  confidence=High
  Ã¢â‚¬Â¦
```
```bash
go install github.com/theworker02/wiretap/cmd/wiretap@v0.5.0
```
```bash
git clone https://github.com/theworker02/wiretap.git
cd wiretap
go build -o bin/wiretap ./cmd/wiretap
```
```bash
go build -ldflags "-X github.com/theworker02/wiretap/pkg/wiretap.Version=0.5.0" -o bin/wiretap ./cmd/wiretap
```
```bash
wiretap doctor
wiretap catalog
wiretap search --ascii HTTP examples/mystery/captures.hex
wiretap analyze examples/mystery/captures.hex
wiretap stats examples/mystery/captures.hex --limit 16
wiretap summary examples/mystery/captures.hex
wiretap explain --at field:0 examples/mystery/captures.hex
wiretap visualize examples/mystery/captures.hex -o map.svg
```
```bash
wiretap format --hex "8a:01:00:0c"
wiretap search --hex DEAD captures.bin
wiretap lint draft.yaml
wiretap catalog
```

Extended evaluation: `docs/acquisition/BUYER_EVALUATION.md`. Written NDA / evaluation grants may be required for private materials.

---

## 6. What a transaction typically includes

Subject to definitive schedules:

| Included (typical) | Excluded (typical) |
|--------------------|--------------------|
| Repo materials + asserted original IP | Seller personal accounts / unrelated repos |
| Docs + diligence room at closing | Third-party dependency source under separate licenses |
| In-repo brand marks as assigned | Secrets without rotation plan |
| Know-how captured in docs | Fabricated revenue, user, or adoption metrics |

---

## 7. Suggested deal structures

| Structure | When it fits |
|-----------|--------------|
| Non-exclusive commercial license | Deploy/run under seat or environment terms |
| Exclusive field-of-use license | Buyer wants exclusivity; seller may retain entity |
| Asset / IP assignment | Buyer wants ownership of Materials outright |
| OEM / redistribution | Separate agreement â€” not implied here |

Commercial terms (price, earnouts, escrow) are negotiated under NDA with counsel.

---

## 8. Buyer diligence checklist

- [ ] Confirm Rightsholder identity and authority to sell/license
- [ ] Inventory Materials (`docs/acquisition/ASSET_INVENTORY.md`)
- [ ] Review IP posture (`IP_PROVENANCE.md`) and dependencies (`DEPENDENCY_INVENTORY.md`)
- [ ] Run evaluation script (`BUYER_EVALUATION.md`)
- [ ] Review risks (`RISK_REGISTER.md`)
- [ ] Agree transfer scope (`TRANSFER_MANIFEST.md`) and handoff (`HANDOFF_CHECKLIST.md`)
- [ ] Supersede root `LICENSE` at closing via definitive agreement

---

## 9. Related documents

| Document | Purpose |
|----------|---------|
| `LICENSE` | Proprietary â€” no default grant |
| `docs/acquisition/README.md` | Data-room index |
| `docs/acquisition/EXECUTIVE_SUMMARY.md` | One-page thesis |
| `README.md` | Product overview |
| `SECURITY.md` | Vulnerability reporting |
| `COMMERCIAL.md` | Licensing contact path |
| `.github/FUNDING.yml` | Sponsors / thanks.dev |

---

## 10. Disclaimer

This package is informational and **does not** create a binding offer, grant of rights, or investment advice. Engage counsel for any transaction.

---

*Document version: 2.0.0 / 2026-09-22 Â· Classification: acquisition briefing*
