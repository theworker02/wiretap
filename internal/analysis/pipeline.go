package analysis

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/theworker02/wiretap/internal/cluster"
	"github.com/theworker02/wiretap/internal/inference"
	"github.com/theworker02/wiretap/internal/project"
	"github.com/theworker02/wiretap/internal/report"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func init() {
	wt.RegisterAnalyzer(func(ctx context.Context, ds *wt.Dataset, opts wt.AnalyzeOptions) (*wt.Result, error) {
		cfg := wt.DefaultPassConfig(opts.Budget)
		if opts.Config != nil {
			cfg = *opts.Config
		}
		p := NewPipeline(Options{
			Budget:      opts.Budget,
			Config:      cfg,
			Passes:      opts.Passes,
			Version:     wt.Version,
			Commit:      wt.Commit,
			Built:       wt.Built,
			Timeout:     opts.Timeout,
			ProjectRoot: opts.ProjectRoot,
			Progress:    opts.Progress,
		})
		return p.Run(ctx, ds)
	})
}

// Options configures the analysis pipeline.
type Options struct {
	Budget      wt.Budget
	Config      wt.PassConfig
	Passes      []wt.Pass
	Version     string
	Commit      string
	Built       string
	Timeout     time.Duration
	Annotations []project.Annotation
	ProjectRoot string
	Progress    wt.ProgressFunc
}

// Pipeline runs separable stages.
type Pipeline struct {
	opts Options
}

// NewPipeline constructs a pipeline.
func NewPipeline(opts Options) *Pipeline {
	if opts.Budget == "" {
		opts.Budget = wt.BudgetNormal
	}
	if opts.Config.MaxCandidates == 0 {
		opts.Config = wt.DefaultPassConfig(opts.Budget)
	}
	return &Pipeline{opts: opts}
}

// Run executes stages: stats → regions → constants → inference passes.
func (p *Pipeline) Run(ctx context.Context, ds *wt.Dataset) (*wt.Result, error) {
	start := time.Now()
	if ds == nil || ds.Len() == 0 {
		return nil, wt.ErrEmptyDataset
	}
	if p.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.opts.Timeout)
		defer cancel()
	}

	cfg := p.opts.Config
	res := &wt.Result{
		SchemaVersion:      wt.ReportVersion,
		ToolVersion:        p.opts.Version,
		ToolCommit:         p.opts.Commit,
		DatasetName:        ds.Name,
		DatasetFingerprint: ds.Fingerprint(),
		Budget:             string(p.opts.Budget),
		MessageCount:       ds.Len(),
		MinLength:          ds.MinLen(),
		MaxLength:          ds.MaxLen(),
		Observations:       []wt.Observation{},
		Hypotheses:         []wt.Hypothesis{},
		Meta:               map[string]string{},
	}
	if ds.Meta["truncated"] == "true" {
		res.Truncated = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("dataset truncated (%s): loaded %s messages",
			ds.Meta["truncated_reason"], ds.Meta["messages_loaded"]))
	}

	if cfg.MaxMessageBytes > 0 {
		for _, m := range ds.Messages {
			if len(m.Data) > cfg.MaxMessageBytes {
				m.Data = m.Data[:cfg.MaxMessageBytes]
				m.Truncated = true
				res.Truncated = true
			}
		}
		if res.Truncated {
			res.Warnings = append(res.Warnings, fmt.Sprintf("messages truncated to %d bytes (budget safety)", cfg.MaxMessageBytes))
			res.DatasetFingerprint = ds.Fingerprint()
			res.MaxLength = ds.MaxLen()
			res.MinLength = ds.MinLen()
		}
	}

	res.ConfigFingerprint = wt.ConfigFingerprint(struct {
		Budget string        `json:"budget"`
		Config wt.PassConfig `json:"config"`
	}{string(p.opts.Budget), cfg})

	// Optional report cache
	if cacheDir := os.Getenv("WIRETAP_CACHE_DIR"); cacheDir != "" {
		if cached, ok, err := report.LoadCachedReport(cacheDir, res.DatasetFingerprint, res.ConfigFingerprint); err == nil && ok {
			cached.SetElapsed(time.Since(start))
			cached.Meta["cache"] = "hit"
			return cached, nil
		}
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", wt.ErrCanceled, ctx.Err())
	default:
	}
	stats := ComputeByteStats(ds)
	res.Stats = stats
	res.Observations = append(res.Observations, wt.Observation{
		Kind: "stage", Description: "byte statistics computed",
		Metrics: map[string]any{"offsets": len(stats)},
	})

	regions := GroupEntropyRegions(stats)
	res.Regions = regions

	constants := DetectConstants(stats)
	res.Constants = constants
	for _, c := range constants {
		val := byte(0)
		if c.Value != nil {
			val = *c.Value
		}
		res.Observations = append(res.Observations, wt.Observation{
			Kind: "constant", Offset: c.Start, Length: c.End - c.Start,
			Description: fmt.Sprintf("constant region value=0x%02x", val),
			Metrics:     map[string]any{"value": val},
		})
	}

	passes := p.opts.Passes
	if passes == nil {
		passes = DefaultPasses()
	}
	passes = wt.FilterPasses(passes, cfg)
	// Attach annotations pass when provided
	anns := p.opts.Annotations
	if len(anns) == 0 && p.opts.ProjectRoot != "" {
		if list, err := project.ListAnnotations(p.opts.ProjectRoot); err == nil {
			anns = list
		}
	}
	if len(anns) > 0 {
		passes = append(passes, inference.AnnotationPass{Annotations: anns})
	}

	in := &wt.PassInput{
		Dataset: ds, Stats: stats, Regions: regions,
		Budget: p.opts.Budget, Config: cfg,
	}

	jobs := cfg.Jobs
	totalPasses := len(passes)
	reportProgress := func(done int, name string) {
		if p.opts.Progress != nil {
			p.opts.Progress(done, totalPasses, name)
		}
	}
	if jobs > 1 && p.opts.Budget != wt.BudgetQuick {
		// Stage A: independent passes in parallel (deterministic merge by name).
		// Stage B: dependent passes (nested) sequentially with merged hypotheses.
		var independent, dependent []wt.Pass
		for _, pass := range passes {
			switch pass.Name() {
			case "nested":
				dependent = append(dependent, pass)
			default:
				independent = append(independent, pass)
			}
		}
		type namedOut struct {
			name string
			out  *wt.PassOutput
			err  error
		}
		ch := make(chan namedOut, len(independent))
		sem := make(chan struct{}, jobs)
		for _, pass := range independent {
			pass := pass
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				o, e := pass.Run(ctx, in)
				ch <- namedOut{pass.Name(), o, e}
			}()
		}
		results := make([]namedOut, 0, len(independent))
		for range independent {
			results = append(results, <-ch)
		}
		sort.Slice(results, func(i, j int) bool { return results[i].name < results[j].name })
		done := 0
		for _, r := range results {
			done++
			reportProgress(done, r.name)
			if r.err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pass %s: %v", r.name, r.err))
				continue
			}
			if r.out == nil {
				continue
			}
			res.Hypotheses = append(res.Hypotheses, r.out.Hypotheses...)
			res.Observations = append(res.Observations, r.out.Observations...)
		}
		in.Hypotheses = res.Hypotheses
		in.Observations = res.Observations
		for _, pass := range dependent {
			done++
			reportProgress(done, pass.Name())
			out, err := pass.Run(ctx, in)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pass %s: %v", pass.Name(), err))
				continue
			}
			if out == nil {
				continue
			}
			res.Hypotheses = append(res.Hypotheses, out.Hypotheses...)
			res.Observations = append(res.Observations, out.Observations...)
			in.Hypotheses = res.Hypotheses
			in.Observations = res.Observations
		}
		res.Meta["pass_parallelism"] = fmt.Sprintf("%d", jobs)
	} else {
		for i, pass := range passes {
			select {
			case <-ctx.Done():
				res.Warnings = append(res.Warnings, "analysis canceled: "+ctx.Err().Error())
				res.SetElapsed(time.Since(start))
				return res, nil
			default:
			}
			reportProgress(i+1, pass.Name())
			out, err := pass.Run(ctx, in)
			if err != nil && ctx.Err() != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pass %s stopped: %v", pass.Name(), err))
				break
			}
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pass %s: %v", pass.Name(), err))
				continue
			}
			if out == nil {
				continue
			}
			res.Hypotheses = append(res.Hypotheses, out.Hypotheses...)
			res.Observations = append(res.Observations, out.Observations...)
			in.Hypotheses = res.Hypotheses
			in.Observations = res.Observations
		}
	}

	// Budget-gated clustering for normal/exhaustive
	if p.opts.Budget != wt.BudgetQuick {
		if cr, err := cluster.ClusterMessages(ds, cluster.Options{MultiSignal: true, SoftAssign: p.opts.Budget == wt.BudgetExhaustive}); err == nil && cr != nil {
			res.Meta["clusters"] = fmt.Sprintf("%d", len(cr.Clusters))
			res.Meta["cluster_hierarchy"] = fmt.Sprintf("%d", len(cr.Hierarchy))
			for _, tf := range cr.TypeFields {
				res.Hypotheses = append(res.Hypotheses, wt.Hypothesis{
					ID: fmt.Sprintf("typefield_o%d_w%d", tf.Offset, tf.Length), Kind: "typefield",
					Offset: tf.Offset, Length: tf.Length, Description: tf.Description,
					Confidence: tf.Confidence, Status: "hypothesis",
					Params: map[string]any{"mapping": tf.Mapping, "width": tf.Length},
				})
			}
			res.Observations = append(res.Observations, wt.Observation{
				Kind: "cluster", Description: fmt.Sprintf("%d clusters discovered (multi-signal)", len(cr.Clusters)),
				Metrics: map[string]any{"clusters": len(cr.Clusters), "type_fields": len(cr.TypeFields), "hierarchy": len(cr.Hierarchy)},
			})
		}
	}

	for _, st := range stats {
		if st.Unique == 1 || st.Entropy > 6 || st.ChangeFrequency > 0.8 {
			res.ByteStatsSummary = append(res.ByteStatsSummary, wt.Observation{
				Kind: "byte_stat", Offset: st.Offset, Length: 1,
				Description: fmt.Sprintf("entropy=%.2f unique=%d const_p=%.2f", st.Entropy, st.Unique, st.ConstantProbability),
				Metrics: map[string]any{
					"entropy": st.Entropy, "unique": st.Unique,
					"mean": st.Mean, "change_frequency": st.ChangeFrequency,
				},
			})
		}
	}

	// Hypothesis competition: prune near-duplicates, rank winners per offset.
	topN := cfg.MaxCandidates
	if topN <= 0 {
		topN = 256
	}
	res.Hypotheses = inference.CompeteHypotheses(res.Hypotheses, topN)

	sort.SliceStable(res.Hypotheses, func(i, j int) bool {
		if res.Hypotheses[i].Confidence.Score == res.Hypotheses[j].Confidence.Score {
			if res.Hypotheses[i].Offset == res.Hypotheses[j].Offset {
				return res.Hypotheses[i].ID < res.Hypotheses[j].ID
			}
			return res.Hypotheses[i].Offset < res.Hypotheses[j].Offset
		}
		return res.Hypotheses[i].Confidence.Score > res.Hypotheses[j].Confidence.Score
	})

	inference.ApplyAnnotationWarnings(res)
	res.SetElapsed(time.Since(start))

	if cacheDir := os.Getenv("WIRETAP_CACHE_DIR"); cacheDir != "" {
		_ = report.CacheReport(cacheDir, res.DatasetFingerprint, res.ConfigFingerprint, res)
	}
	return res, nil
}

// DefaultPasses returns the built-in inference pass list.
func DefaultPasses() []wt.Pass {
	return []wt.Pass{
		inference.IntegerPass{},
		inference.LengthFieldPass{},
		inference.CounterPass{},
		&inference.ChecksumPass{},
		inference.StringPass{},
		inference.BitfieldPass{},
		inference.StructuredPass{},
		inference.TimestampPass{},
		inference.ArrayPass{},
		inference.NestedPass{},
		inference.TLVPass{},
		inference.VarintPass{},
		inference.EntropyClassPass{},
	}
}
