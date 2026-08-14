# TUI

`wiretap tui` opens an interactive browser over an analysis report.

```bash
wiretap tui examples/mystery/captures.hex
```

Typical session: load captures → browse hypotheses, entropy, and clusters →
`explain` at an offset → quit. Keys are printed in the UI (section numbers,
`x <offset>`, `q`).

The TUI is a presentation layer over the same offline pipeline as
`wiretap analyze`. It does not capture network traffic.
