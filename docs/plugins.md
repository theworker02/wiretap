# Wiretap plugins / Pass API

Wiretap inference is a pipeline of **Pass** implementations.

## Public API (`pkg/wiretap`)

```go
type Pass interface {
    Name() string
    Run(ctx context.Context, in *PassInput) (*PassOutput, error)
}

func RegisterPass(p Pass)
func LookupPass(name string) (Pass, bool)
func RegisteredPasses() []string
func FilterPasses(passes []Pass, cfg PassConfig) []Pass
```

`PassConfig` supports:

- `DisabledPasses []string` — skip by name
- `EnabledPasses []string` — if non-empty, only these run
- `Jobs int` — pass-level parallelism (independent passes; nested runs after)

## Example

See [`examples/plugins/sample_pass.go`](../examples/plugins/sample_pass.go).

In a custom binary:

```go
import (
    _ "your.module/samplepass" // registers via init
    wt "github.com/theworker02/wiretap/pkg/wiretap"
)

res, err := wt.Analyze(ctx, ds, wt.AnalyzeOptions{
    Budget: wt.BudgetNormal,
    Passes: append(defaultPasses, mustLookup("example_magic_th")),
})
```

## Rules

- Prefer **Insufficient evidence** over hype
- Emit measurable `EvidenceItem` weights — never invent confidence
- Keep passes deterministic and offline
- Do not perform network acquisition inside a Pass
