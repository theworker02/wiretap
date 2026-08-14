package wiretap

import (
	"context"
	"time"
)

// Version metadata set via ldflags.
var (
	Version = "0.4.0"
	Commit  = "none"
	Built   = "unknown"
)

// analyzeFunc is set by the analysis package via RegisterAnalyzer to avoid import cycles.
var analyzeFunc func(ctx context.Context, ds *Dataset, opts AnalyzeOptions) (*Result, error)

// RegisterAnalyzer wires the internal pipeline into the public API.
// Called from an init in the analysis bootstrap package used by the CLI and tests.
func RegisterAnalyzer(fn func(ctx context.Context, ds *Dataset, opts AnalyzeOptions) (*Result, error)) {
	analyzeFunc = fn
}

// Analyzer runs protocol inference.
type Analyzer interface {
	Analyze(ctx context.Context, ds *Dataset) (*Result, error)
}

// ProgressFunc reports analysis progress (pass index is 1-based).
// Intended for stderr TTY UX — never write progress to the report stdout stream.
type ProgressFunc func(done, total int, passName string)

// AnalyzeOptions configures Analyze.
type AnalyzeOptions struct {
	Budget      Budget
	Timeout     time.Duration
	Passes      []Pass
	Config      *PassConfig
	ProjectRoot string // when set, annotations are loaded and treated as trusted evidence
	Progress    ProgressFunc
}

// DefaultAnalyzer is the standard Wiretap analyzer.
type DefaultAnalyzer struct {
	Opts AnalyzeOptions
}

// NewAnalyzer constructs an analyzer.
func NewAnalyzer(opts AnalyzeOptions) *DefaultAnalyzer {
	if opts.Budget == "" {
		opts.Budget = BudgetNormal
	}
	return &DefaultAnalyzer{Opts: opts}
}

// Analyze implements Analyzer.
func (a *DefaultAnalyzer) Analyze(ctx context.Context, ds *Dataset) (*Result, error) {
	return Analyze(ctx, ds, a.Opts)
}

// Analyze is a convenience entry point.
func Analyze(ctx context.Context, ds *Dataset, opts AnalyzeOptions) (*Result, error) {
	if analyzeFunc == nil {
		return nil, ErrNotRegistered
	}
	if opts.Budget == "" {
		opts.Budget = BudgetNormal
	}
	return analyzeFunc(ctx, ds, opts)
}

// ParseBudget parses a budget string.
func ParseBudget(s string) (Budget, error) {
	switch Budget(s) {
	case BudgetQuick, BudgetNormal, BudgetExhaustive:
		return Budget(s), nil
	case "":
		return BudgetNormal, nil
	default:
		return "", ErrInvalidConfig
	}
}
