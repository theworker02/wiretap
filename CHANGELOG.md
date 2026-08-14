# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-08-14

### Added

- `Dataset.Search` — find non-overlapping hex or ASCII byte patterns with message identity, offset, and surrounding context
- `wiretap search --hex` / `--ascii` — CLI over that API (`--format json` supported)

### Changed

- Default version **0.5.0**

## [0.4.0] — 2026-08-13

Unified product release under **[@theworker02](https://github.com/theworker02)**.

### Added

- `wiretap catalog` — browse bundled examples via `examples/catalog.yaml`
- `wiretap lint` / `schema lint` — schema hygiene (overlaps, endian, unnamed fields)
- `wiretap format` — normalize / pretty-print tolerant hex input
- `ORGANIZATION.md` — maintainer identity (@theworker02)
- Redesigned logo / mark / favicon / social preview
- Polished GitHub Pages site (`docs-site/`)
- `.github/FUNDING.yml` — `github: theworker02` + `thanks_dev: u/gh/theworker02`
- Logo headers on every package/example README
- Report cache helpers in `internal/report`; synth corpus in `internal/eval`

### Changed

- Module path **`github.com/theworker02/wiretap`**
- Default version **0.4.0**
- Project metadata writes `wiretap: 0.4.0` (no `phase1` tags)
- Pipeline comments describe **stages**, not bolted-on phases
- Flagship README rewritten as a product page for @theworker02

### Removed

- Standalone `internal/storage` (merged into `internal/report`)
- Standalone `internal/synth` (merged into `internal/eval`)
- Former `wiretap-os` module / org branding

### Notes

- Measured eval floors unchanged; see `wiretap eval` and `docs/eval.md`
- GitHub Pages sources remain in `docs-site/`; enable Actions Pages to publish

## [0.3.0] — 2026

HTML reports, doctor/docs/completion/notes, Mermaid visualize, competition
precision improvements, OSS packaging (CODE_OF_CONDUCT, Dependabot, FUNDING,
CITATION, docs-site), expansive CLI groups (`stats`, `dump`, `summary`, …).

Measured eval (seed=1, n=50, normal): precision ≈ 0.83, FPR ≈ 0.17, recall = 1.0.

## [0.2.0] — 2025

Nested/array inference, Bubble Tea TUI, Kaitai/Wireshark generators, index,
visualize, capture/watch, plugins API, PCAPNG, eval harness, examples expansion.

## [0.1.0] — 2025

Initial public toolkit: ingest, stats, inference passes, projects, reports,
public Go API, mystery example, CI.

[0.5.0]: https://github.com/theworker02/wiretap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/theworker02/wiretap/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/theworker02/wiretap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/theworker02/wiretap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/theworker02/wiretap/releases/tag/v0.1.0
