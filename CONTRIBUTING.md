# Contributing to Wiretap

Thanks for helping build an evidence-backed protocol analysis toolkit.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Scope

Wiretap is for **authorized / legitimate** binary analysis: your own protocols,
lab captures you are permitted to study, CTF-style challenges you own, and
defensive reverse engineering.

Do **not** contribute features whose primary purpose is covert interception,
unauthorized access, or malware tooling. Analysis is deliberately separate from
packet acquisition. PCAP/PCAPNG and drop-folder ingest are **operator-provided
files only**.

## Plugins

Implement `wiretap.Pass`, call `wiretap.RegisterPass`, and document enable/disable
via `PassConfig.DisabledPasses` / `EnabledPasses`. See [docs/plugins.md](docs/plugins.md)
and `examples/plugins/sample_pass.go`.

## Development

```bash
make build
make test
make race
make lint
make fuzz
make bench
make eval
make visualize
make doctor   # when bin/wiretap is built
```

On Windows without GNU Make, use the equivalent `go` commands — see
[docs/windows.md](docs/windows.md). Demo scripts: `scripts/demo.sh`,
`scripts/demo.ps1`.

- Prefer table-driven tests and fuzz targets for parsers/checksums/schema/pcap.
- Prefer golden tests when locking report / eval shape.
- Never invent confidence scores — attach measurable evidence or report Unknown.
- Keep CLI stdout clean for reports; put diagnostics on stderr behind `-v`.
- Do not add LLM/network telemetry dependencies.
- Do not commit binaries (`bin/`, release artifacts).

## Docs

Docs live under [`docs/`](docs/README.md). Update the index when adding pages.
Brand tokens and assets: [`docs/brand.md`](docs/brand.md), [`assets/`](assets/).
Public site sources: [`docs-site/`](docs-site/) (plain HTML; see that folder’s README for local preview).
When changing logos, copy SVGs into `docs-site/assets/` or rely on the Pages workflow sync step.

## Funding

Optional sponsor button config: [`.github/FUNDING.yml`](.github/FUNDING.yml).
Entries are **commented placeholders** by default so GitHub does not show broken
links. To enable Sponsors / Ko-fi / Liberapay / custom URLs:

1. Uncomment the relevant keys in `.github/FUNDING.yml`
2. Replace usernames / URLs with real accounts you control
3. Confirm the Sponsor button appears on the repo once GitHub indexes the file

Support routing for users: [`.github/SUPPORT.md`](.github/SUPPORT.md).

## Releases

Version **0.5.0** line. Tagged releases (`v*`) use GoReleaser
(`.goreleaser.yml`, `.github/workflows/release.yml`).

```bash
make release-snapshot
# or: goreleaser release --snapshot --clean
```

See [CHANGELOG.md](CHANGELOG.md).

## Pull requests

- Small, focused changes; conventional commits welcome.
- Update docs when CLI behavior changes.
- Include tests for inference logic whenever possible.
- Use the PR template checklist.
