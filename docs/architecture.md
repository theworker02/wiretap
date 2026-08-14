# Architecture

Wiretap separates **acquisition** from **inference** from **presentation**.

```
┌──────────────┐    ┌───────────────────┐    ┌─────────────────┐
│  Importers / │───▶│ Inference engine  │───▶│ Structured      │
│  CaptureSrc  │    │ passes + compete  │    │ Report (JSON)   │
│  hex/bin/    │    │ cluster / index   │    └────────┬────────┘
│  pcapng/dir  │    └───────────────────┘             │
└──────────────┘                                      ▼
                                           CLI / TUI / SVG / codegen
```

## Principles

1. **Observation vs hypothesis** — measured facts vs evidence-backed guesses
2. **Competing candidates** — pruned/ranked per offset; losers explained
3. **Determinism** — same inputs ⇒ same ordered outputs (`--jobs` merges by name)
4. **Budgets** — `quick` / `normal` / `exhaustive`
5. **Extensibility** — public `Pass` registry (`RegisterPass` / `FilterPasses`)
6. **Annotations trusted** — never auto-overwritten
7. **Honest entropy** — never claim “encrypted” without caveats

## Packages

| Path | Role |
|------|------|
| `pkg/wiretap` | Public API + Pass plugin registry |
| `internal/capture` | Hex/binary/PCAPNG + drop-folder sources |
| `internal/analysis` | Pipeline, parallel passes, clustering hook |
| `internal/inference` | Field/checksum/array/TLV/varint/entropy/nested/compete |
| `internal/cluster` | Multi-signal clustering + type fields |
| `internal/index` | On-disk sample index / incremental |
| `internal/visualize` | SVG/HTML field maps |
| `internal/compare` | Diff + correlation + experiments |
| `internal/eval` | Synthetic corpus + measured evaluation |
| `internal/report` | Text / JSON / HTML rendering + report cache |
| `internal/tui` | Interactive report browser |
| `schema` | AST, diff/merge, Go/Kaitai/Wireshark codegen |

## Determinism with `--jobs`

Independent passes run in a bounded worker pool; outputs merge sorted by pass
name. Dependent passes (`nested`) run afterward on the merged hypothesis set.
