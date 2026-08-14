# Security Policy

**Wiretap 0.4.0** — evidence-backed binary protocol analysis.

## Authorized use only

Wiretap is a protocol **analysis** toolkit for data you are authorized to study.

It does **not**:

- Tap or MITM networks
- Bypass authentication or encryption
- Provide remote exploit helpers
- Silently capture third-party traffic

Capture helpers (`wiretap capture`, `wiretap watch`, PCAP ingest / `--follow`) only
load **operator-provided** files/directories/stdin. `--follow` tails a growing PCAP
file on disk; it does not open network interfaces or require Npcap. Acquisition is
separate from analysis.

See [docs/capture-ethics.md](docs/capture-ethics.md).

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes |
| 0.3.x   | Security fixes as feasible |
| < 0.3   | No |

## Reporting vulnerabilities

Report security issues privately via a **GitHub security advisory** (preferred,
when the repository has advisories enabled).

Placeholder email until a real inbox is configured: **security@wiretap.local**
(maintainer: replace this with a monitored address). Do not assume mail to the
placeholder is delivered.

Include: Wiretap version/commit (`wiretap version` / `wiretap doctor` when available),
reproduction on synthetic data, and impact.

Do not file public issues for undisclosed vulnerabilities.

## Design notes

- Offline by default; no telemetry; no LLM/cloud model calls
- Malformed input must not panic
- Generated parsers use bounds checks and typed errors
- Analysis budgets and candidate caps limit resource exhaustion
- Confidence is evidence-derived — never invented
