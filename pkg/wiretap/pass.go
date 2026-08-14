package wiretap

import (
	"context"
	"sort"
	"sync"
)

// Pass is an extensible inference stage.
// External plugins implement this interface and register via RegisterPass.
type Pass interface {
	Name() string
	Run(ctx context.Context, in *PassInput) (*PassOutput, error)
}

// PassInput is shared state for inference passes.
type PassInput struct {
	Dataset      *Dataset
	Stats        []ByteStat
	Regions      []Region
	Budget       Budget
	Config       PassConfig
	Hypotheses   []Hypothesis
	Observations []Observation
}

// PassOutput merges pass results.
type PassOutput struct {
	Hypotheses   []Hypothesis
	Observations []Observation
}

// PassConfig holds safety limits for inference.
type PassConfig struct {
	MaxCandidates    int
	TimeoutPerPass   int // milliseconds hint; context is authoritative
	MaxMessageBytes  int
	EnableChecksum   bool
	EnableStrings    bool
	EnableBitfields  bool
	EnableStructured bool
	EnableTimestamps bool
	// DisabledPasses / EnabledPasses control the public plugin/pass system.
	DisabledPasses []string `json:"disabled_passes,omitempty"`
	EnabledPasses  []string `json:"enabled_passes,omitempty"` // if non-empty, only these run
	Jobs           int      `json:"jobs,omitempty"`           // pass-level parallelism hint (0 = sequential)
}

// DefaultPassConfig returns safe defaults for a budget.
func DefaultPassConfig(b Budget) PassConfig {
	c := PassConfig{
		EnableChecksum:   true,
		EnableStrings:    true,
		EnableBitfields:  true,
		EnableStructured: true,
		EnableTimestamps: true,
	}
	switch b {
	case BudgetQuick:
		c.MaxCandidates = 64
		c.TimeoutPerPass = 2000
		c.MaxMessageBytes = 4096
	case BudgetExhaustive:
		c.MaxCandidates = 2000
		c.TimeoutPerPass = 120000
		c.MaxMessageBytes = 1 << 20
	default: // normal — prefer fewer high-quality hyps after competition prune
		c.MaxCandidates = 160
		c.TimeoutPerPass = 15000
		c.MaxMessageBytes = 65536
	}
	return c
}

var (
	passMu       sync.RWMutex
	passRegistry = map[string]Pass{}
)

// RegisterPass adds a named Pass to the global registry (stable public plugin API).
func RegisterPass(p Pass) {
	if p == nil {
		return
	}
	passMu.Lock()
	defer passMu.Unlock()
	passRegistry[p.Name()] = p
}

// LookupPass returns a registered pass by name.
func LookupPass(name string) (Pass, bool) {
	passMu.RLock()
	defer passMu.RUnlock()
	p, ok := passRegistry[name]
	return p, ok
}

// RegisteredPasses returns sorted pass names.
func RegisteredPasses() []string {
	passMu.RLock()
	defer passMu.RUnlock()
	names := make([]string, 0, len(passRegistry))
	for n := range passRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// FilterPasses applies PassConfig enable/disable lists.
func FilterPasses(passes []Pass, cfg PassConfig) []Pass {
	disabled := map[string]bool{}
	for _, n := range cfg.DisabledPasses {
		disabled[n] = true
	}
	enabledOnly := len(cfg.EnabledPasses) > 0
	enabled := map[string]bool{}
	for _, n := range cfg.EnabledPasses {
		enabled[n] = true
	}
	out := make([]Pass, 0, len(passes))
	for _, p := range passes {
		if p == nil {
			continue
		}
		name := p.Name()
		if disabled[name] {
			continue
		}
		if enabledOnly && !enabled[name] {
			continue
		}
		out = append(out, p)
	}
	return out
}
