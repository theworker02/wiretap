package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/theworker02/wiretap/internal/analysis"
	"github.com/theworker02/wiretap/internal/capture"
	"github.com/theworker02/wiretap/internal/cluster"
	"github.com/theworker02/wiretap/internal/compare"
	"github.com/theworker02/wiretap/internal/inference"
	"github.com/theworker02/wiretap/internal/project"
	"github.com/theworker02/wiretap/internal/report"
	"github.com/theworker02/wiretap/internal/tui"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

var (
	flagFormat      string
	flagBudget      string
	flagVerbose     int
	flagColor       bool
	flagTimeout     time.Duration
	flagInput       string
	flagBinary      bool
	flagProject     string
	flagMaxMessages int
	flagSchemaFmt   string
	flagPCAP        string
	flagJobs        int
)

func main() {
	root := &cobra.Command{
		Use:           "wiretap",
		Short:         "Evidence-backed binary protocol inference",
		Long:          rootLongHelp + "\n\nWiretap 0.5 — Wiretap OS product line. Run wiretap about for org details.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       wt.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if flagVerbose > 0 {
				logf(1, "verbose=%d", flagVerbose)
			}
		},
	}
	registerCommandGroups(root)
	root.SetVersionTemplate("wiretap {{.Version}}\n")
	root.PersistentFlags().CountVarP(&flagVerbose, "verbose", "v", "verbose logging (-v/-vv/-vvv); separate from clean CLI/JSON output")
	root.PersistentFlags().StringVar(&flagFormat, "format", "text", "output format: text|json|html")
	root.PersistentFlags().StringVar(&flagBudget, "budget", "normal", "analysis budget: quick|normal|exhaustive")
	root.PersistentFlags().BoolVar(&flagColor, "color", true, "colorize text output (disabled when NO_COLOR is set)")
	root.PersistentFlags().DurationVar(&flagTimeout, "timeout", 0, "analysis timeout (0 = none beyond budget)")
	root.PersistentFlags().StringVarP(&flagInput, "input", "i", "", "input file, directory, or - for stdin")
	root.PersistentFlags().BoolVar(&flagBinary, "binary", false, "treat input as raw binary")
	root.PersistentFlags().StringVar(&flagProject, "project", "", "project root (loads annotations as trusted evidence)")
	root.PersistentFlags().IntVar(&flagMaxMessages, "max-messages", 0, "cap messages loaded (records truncation in report)")
	root.PersistentFlags().StringVar(&flagSchemaFmt, "schema-format", "", "schema codec: json|yaml (default: by extension)")
	root.PersistentFlags().StringVar(&flagPCAP, "pcap", "", "analyze payloads from a PCAP/PCAPNG file (authorized captures only)")
	root.PersistentFlags().IntVar(&flagJobs, "jobs", 0, "pass-level parallelism (0=sequential; deterministic merge)")

	projectCmd := cmdProject()
	expandProjectCommand(projectCmd)
	sampleCmd := cmdSample()
	expandSampleCommand(sampleCmd)
	annotateCmd := cmdAnnotate()
	expandAnnotateCommand(annotateCmd)

	root.AddCommand(
		// Analysis
		setGroup(cmdAnalyze(), "analysis"),
		setGroup(cmdSummary(), "analysis"),
		setGroup(cmdStats(), "analysis"),
		setGroup(cmdDump(), "analysis"),
		setGroup(cmdSearch(), "analysis"),
		setGroup(cmdHypotheses(), "analysis"),
		setGroup(cmdExplain(), "analysis"),
		setGroup(cmdInspect(), "analysis"),
		setGroup(cmdDiff(), "analysis"),
		setGroup(cmdCorrelate(), "analysis"),
		setGroup(cmdCluster(), "analysis"),
		setGroup(cmdEntropy(), "analysis"),
		setGroup(cmdChecksum(), "analysis"),
		setGroup(cmdStrings(), "analysis"),
		setGroup(cmdTimestamps(), "analysis"),
		setGroup(cmdFingerprint(), "analysis"),
		setGroup(cmdExport(), "analysis"),
		setGroup(wrapEval(), "analysis"),
		setGroup(cmdExperiment(), "analysis"),
		setGroup(cmdTUI(), "analysis"),
		setGroup(cmdVisualize(), "analysis"),
		setGroup(cmdReport(), "analysis"),
		setGroup(cmdReplay(), "analysis"),
		setGroup(cmdFormat(), "analysis"),
		setGroup(cmdLint(), "schema"),
		setGroup(cmdCatalog(), "tooling"),
		// Project
		setGroup(cmdInitAlias(), "project"),
		setGroup(projectCmd, "project"),
		setGroup(sampleCmd, "project"),
		setGroup(annotateCmd, "project"),
		setGroup(cmdUnannotate(), "project"),
		setGroup(cmdNote(), "project"),
		// Schema
		setGroup(cmdSchema(), "schema"),
		setGroup(cmdValidate(), "schema"),
		setGroup(wrapGenerate(), "schema"),
		setGroup(cmdCompareSchemas(), "schema"),
		// Capture
		setGroup(cmdIndex(), "capture"),
		setGroup(cmdWatch(), "capture"),
		setGroup(cmdCapture(), "capture"),
		// Tooling
		setGroup(cmdPasses(), "tooling"),
		setGroup(cmdConfig(), "tooling"),
		setGroup(cmdEnv(), "tooling"),
		setGroup(cmdDoctor(), "tooling"),
		setGroup(cmdDocs(), "tooling"),
		setGroup(cmdAbout(), "tooling"),
		setGroup(cmdCompletion(), "tooling"),
		setGroup(cmdHelpAll(), "tooling"),
		setGroup(cmdBenchInfo(), "tooling"),
		setGroup(cmdVersion(), "tooling"),
		cmdNow(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func logf(min int, format string, args ...any) {
	if flagVerbose < min {
		return
	}
	fmt.Fprintf(os.Stderr, "wiretap: "+format+"\n", args...)
}

func parseBudget() (wt.Budget, error) {
	b, err := wt.ParseBudget(flagBudget)
	if err != nil {
		return "", fmt.Errorf("%w: budget must be quick|normal|exhaustive (got %q)", wt.ErrInvalidConfig, flagBudget)
	}
	return b, nil
}

func parseFormat() (report.Format, error) {
	switch strings.ToLower(flagFormat) {
	case "text", "":
		return report.FormatText, nil
	case "json":
		return report.FormatJSON, nil
	case "html":
		return report.FormatHTML, nil
	default:
		return "", fmt.Errorf("%w: format must be text|json|html (got %q)", wt.ErrUnsupportedFmt, flagFormat)
	}
}

func loadDataset(args []string) (*wt.Dataset, error) {
	if flagPCAP != "" {
		logf(1, "loading pcap %s", flagPCAP)
		return capture.ImportPCAP(flagPCAP, capture.LoadOptions{
			Binary: true, MaxMessages: flagMaxMessages,
		})
	}
	in := flagInput
	if in == "" && len(args) > 0 {
		in = args[0]
	}
	// Inside a project with no args → use samples/
	if in == "" {
		root := flagProject
		if root == "" {
			if r, err := project.FindRoot("."); err == nil {
				root = r
			}
		}
		if root != "" {
			logf(1, "loading project samples from %s", root)
			ds, err := project.LoadSamples(root)
			if err != nil {
				return nil, err
			}
			if flagMaxMessages > 0 && ds.Len() > flagMaxMessages {
				ds.Messages = ds.Messages[:flagMaxMessages]
				captureMark := ds.Meta
				if captureMark == nil {
					ds.Meta = map[string]string{}
				}
				ds.Meta["truncated"] = "true"
				ds.Meta["truncated_reason"] = "max_messages"
				ds.Meta["messages_loaded"] = fmt.Sprintf("%d", ds.Len())
			}
			return ds, nil
		}
	}
	opts := capture.LoadOptions{Binary: flagBinary, OnePerLine: true, MaxMessages: flagMaxMessages}
	if in == "" || in == "-" {
		logf(1, "loading stdin")
		return capture.LoadReader(os.Stdin, "stdin", opts)
	}
	// Auto-detect pcap by extension
	lower := strings.ToLower(in)
	if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
		return capture.ImportPCAP(in, opts)
	}
	logf(1, "loading %s", in)
	return capture.LoadPath(in, opts)
}

func projectRootForAnalyze() string {
	if flagProject != "" {
		return flagProject
	}
	if r, err := project.FindRoot("."); err == nil {
		return r
	}
	return ""
}

func cmdAnalyze() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:     "analyze [path]",
		Aliases: []string{"a", "an"},
		Short:   "Run the full inference pipeline on a capture dataset",
		Long:    "With no path inside a wiretap project, analyzes samples/. Use --project to load annotations as trusted evidence. --pcap imports authorized PCAP payloads (analysis ≠ acquisition). Progress prints to stderr when stderr is a TTY.",
		Args:    cobra.MaximumNArgs(1),
		Example: `  wiretap analyze examples/mystery/captures.hex
  wiretap analyze --format json -o reports/last.json examples/mystery/captures.hex
  wiretap analyze --format html -o report.html examples/thermostat/captures.hex
  wiretap a captures.hex --budget quick --jobs 4`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			if ds.Len() == 0 {
				return wt.ErrEmptyDataset
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			fmtFormat, err := parseFormat()
			if err != nil {
				return err
			}
			root := projectRootForAnalyze()
			logf(2, "dataset messages=%d fingerprint=%s project=%q", ds.Len(), ds.Fingerprint(), root)
			cfg := wt.DefaultPassConfig(budget)
			cfg.Jobs = flagJobs
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
				Budget: budget, Timeout: flagTimeout, ProjectRoot: root, Config: &cfg,
				Progress: progressReporter(),
			})
			if err != nil {
				return err
			}
			logf(1, "hypotheses=%d elapsed_ms=%d elapsed_us=%d", len(res.Hypotheses), res.ElapsedMS, res.ElapsedUS)
			saveLastReport(res)

			var w = os.Stdout
			if out != "" && out != "-" {
				if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && filepath.Dir(out) != "." {
					return err
				}
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			if err := report.Write(w, res, ds, fmtFormat, flagColor); err != nil {
				return err
			}
			if out != "" && out != "-" {
				fmt.Fprintf(os.Stderr, "wrote %s\n", out)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write report to file (stdout when empty)")
	return c
}

func cmdDiff() *cobra.Command {
	var label, a, b, correlate string
	c := &cobra.Command{
		Use:   "diff [path]",
		Short: "Differential comparison between label cohorts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			if label == "" || a == "" || b == "" {
				return fmt.Errorf("%w: require --label, --a, and --b", wt.ErrInvalidLabel)
			}
			diff, err := compare.Diff(ds, label, a, b)
			if err != nil {
				return err
			}
			if correlate != "" {
				corr, err := compare.CorrelateNumeric(ds, correlate, 0)
				if err != nil {
					logf(1, "correlation skipped: %v", err)
				} else {
					diff.Correlations = corr
				}
			}
			fmtFormat, err := parseFormat()
			if err != nil {
				return err
			}
			if fmtFormat == report.FormatJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(diff)
			}
			fmt.Printf("Diff %s: %s(%d) vs %s(%d)\n", diff.LabelKey, diff.CohortA, diff.CountA, diff.CohortB, diff.CountB)
			fmt.Println("Changed regions:")
			if len(diff.Changed) == 0 {
				fmt.Println("  (none detected — cohorts may share identical byte sets)")
			}
			for _, r := range diff.Changed {
				fmt.Printf("  [%d:%d] confidence=%s\n", r.Start, r.End, r.Confidence.Level)
			}
			if len(diff.Correlations) > 0 {
				fmt.Println("Correlations:")
				for _, c := range diff.Correlations {
					fmt.Printf("  %s  conf=%s  %s\n", c.Method, c.Confidence.Level, c.Description)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&label, "label", "", "label key to split on")
	c.Flags().StringVar(&a, "a", "", "cohort A label value")
	c.Flags().StringVar(&b, "b", "", "cohort B label value")
	c.Flags().StringVar(&correlate, "correlate", "", "numeric label key for field correlation")
	return c
}

func cmdCluster() *cobra.Command {
	return &cobra.Command{
		Use:   "cluster [path]",
		Short: "Cluster messages by length, constant prefix, and similarity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			res, err := cluster.ClusterMessages(ds, cluster.Options{})
			if err != nil {
				return err
			}
			fmtFormat, _ := parseFormat()
			if fmtFormat == report.FormatJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Printf("Clusters: %d\n", len(res.Clusters))
			for _, c := range res.Clusters {
				fmt.Printf("  %s size=%d len=%d prefix=%x\n", c.ID, c.Size, c.Length, c.ConstantPref)
			}
			for _, t := range res.TypeFields {
				fmt.Printf("type-field candidate off=%d conf=%s — %s\n", t.Offset, t.Confidence.Level, t.Description)
			}
			return nil
		},
	}
}

func cmdEntropy() *cobra.Command {
	return &cobra.Command{
		Use:   "entropy [path]",
		Short: "Show per-offset entropy map and region grouping",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			stats := analysis.ComputeByteStats(ds)
			regions := analysis.GroupEntropyRegions(stats)
			fmtFormat, _ := parseFormat()
			if fmtFormat == report.FormatJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"stats":   toPublicStats(stats),
					"regions": toPublicRegions(regions),
				})
			}
			fmt.Println("Offset  Entropy  Unique  ConstP  ChangeFreq")
			for _, s := range stats {
				n := int(s.Entropy + 0.5)
				bar := strings.Repeat("#", n)
				fmt.Printf("%6d  %7.3f  %6d  %6.2f  %10.2f  %s\n", s.Offset, s.Entropy, s.Unique, s.ConstantProbability, s.ChangeFrequency, bar)
			}
			fmt.Println("\nRegions:")
			for _, r := range regions {
				fmt.Printf("  [%d:%d] %s entropy_mean=%.2f\n", r.Start, r.End, r.Kind, r.EntropyMean)
			}
			return nil
		},
	}
}

func toPublicStats(stats []analysis.ByteStats) []wt.ByteStat {
	out := make([]wt.ByteStat, len(stats))
	for i, s := range stats {
		out[i] = wt.ByteStat{
			Offset: s.Offset, Count: s.Count, Unique: s.Unique,
			Min: s.Min, Max: s.Max, Mean: s.Mean, Median: s.Median,
			Mode: s.Mode, ModeCount: s.ModeCount, Variance: s.Variance, StdDev: s.StdDev,
			Entropy: s.Entropy, ChangeFrequency: s.ChangeFrequency,
			ConstantProbability: s.ConstantProbability,
		}
	}
	return out
}

func toPublicRegions(regions []analysis.Region) []wt.Region {
	out := make([]wt.Region, len(regions))
	for i, r := range regions {
		out[i] = wt.Region(r)
	}
	return out
}

func cmdChecksum() *cobra.Command {
	return &cobra.Command{
		Use:   "checksum [path]",
		Short: "Run checksum discovery only",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
				Budget: budget,
				Passes: []wt.Pass{&inference.ChecksumPass{}},
			})
			if err != nil {
				return err
			}
			fmtFormat, _ := parseFormat()
			return report.Write(os.Stdout, res, ds, fmtFormat, flagColor)
		},
	}
}

func cmdInspect() *cobra.Command {
	var offset int
	c := &cobra.Command{
		Use:   "inspect [path]",
		Short: "Inspect dataset metadata, byte stats, and hypotheses at an offset",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			stats := analysis.ComputeByteStats(ds)
			fmtFormat, _ := parseFormat()
			info := map[string]any{
				"name":        ds.Name,
				"messages":    ds.Len(),
				"min_length":  ds.MinLen(),
				"max_length":  ds.MaxLen(),
				"fingerprint": ds.Fingerprint(),
				"label_keys":  ds.LabelKeys(),
				"offsets":     len(stats),
			}
			var top []wt.Hypothesis
			if cmd.Flags().Changed("offset") {
				budget, err := parseBudget()
				if err != nil {
					return err
				}
				res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
					Budget: budget, ProjectRoot: projectRootForAnalyze(),
				})
				if err != nil {
					return err
				}
				top = inference.ExplainCompetition(res.Hypotheses, offset, offset+1, 8)
				info["offset"] = offset
				info["hypotheses_at_offset"] = top
			}
			if fmtFormat == report.FormatJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			fmt.Printf("Dataset %q\nmessages=%d lengths=%d..%d\nfingerprint=%s\nlabels=%v\n",
				ds.Name, ds.Len(), ds.MinLen(), ds.MaxLen(), ds.Fingerprint(), ds.LabelKeys())
			for i, m := range ds.Messages {
				if i >= 5 {
					fmt.Printf("… %d more\n", ds.Len()-5)
					break
				}
				fmt.Printf("  %s len=%d labels=%s src=%s\n", m.ID, len(m.Data), wt.JoinLabels(m.Labels), m.Source.Path)
			}
			if cmd.Flags().Changed("offset") {
				fmt.Printf("\nHypotheses at offset %d:\n", offset)
				for _, h := range top {
					fmt.Printf("  %s %s conf=%s — %s\n", h.ID, h.Kind, h.Confidence.Level, h.Description)
				}
			}
			return nil
		},
	}
	c.Flags().IntVar(&offset, "offset", -1, "show competing hypotheses at this offset")
	return c
}

func cmdExplain() *cobra.Command {
	var hypID, selector string
	c := &cobra.Command{
		Use:   "explain [path]",
		Short: "Explain a hypothesis by --id or an offset/field selector",
		Long:  "Selectors: --id SUBSTR | --at field:N | --at 0xNN | --at offset:N | --at 0x02..0x03\nShows competing hypotheses at that range with evidence for/against.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hypID == "" && selector == "" {
				return fmt.Errorf("%w: require --id or --at selector", wt.ErrInvalidConfig)
			}
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
				Budget: budget, ProjectRoot: projectRootForAnalyze(),
			})
			if err != nil {
				return err
			}
			selStr := selector
			if selStr == "" {
				selStr = hypID
			}
			sel, err := report.ParseSelector(selStr)
			if err != nil {
				return err
			}
			if hypID != "" && selector == "" {
				sel = report.Selector{Kind: "id", ID: hypID}
			}
			return report.Explain(os.Stdout, res, sel)
		},
	}
	c.Flags().StringVar(&hypID, "id", "", "hypothesis id (or substring)")
	c.Flags().StringVar(&selector, "at", "", "field:N | 0xNN | offset:N | 0xAA..0xBB")
	return c
}

func cmdCorrelate() *cobra.Command {
	var label string
	c := &cobra.Command{
		Use:   "correlate [path]",
		Short: "Correlate a numeric label with message bytes (alias of diff --correlate)",
		Long:  "Bounded transform search correlating a numeric label against candidate integer fields. Prefer: wiretap diff --label … --correlate KEY.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				return fmt.Errorf("%w: --label required", wt.ErrInvalidLabel)
			}
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			corr, err := compare.CorrelateNumeric(ds, label, 0)
			if err != nil {
				return err
			}
			fmtFormat, _ := parseFormat()
			if fmtFormat == report.FormatJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(corr)
			}
			fmt.Println("Correlations:")
			for _, c := range corr {
				fmt.Printf("  %s  conf=%s  %s\n", c.Method, c.Confidence.Level, c.Description)
			}
			return nil
		},
	}
	c.Flags().StringVar(&label, "label", "", "numeric label key")
	return c
}

func cmdAnnotate() *cobra.Command {
	var offset, length int
	var kind, label, note, id string
	c := &cobra.Command{
		Use:   "annotate",
		Short: "Add a human annotation to the current project (never overwrites)",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			path, err := project.Annotate(root, project.Annotation{
				ID: id, Offset: offset, Length: length, Kind: kind, Label: label, Note: note,
			})
			if err != nil {
				return err
			}
			fmt.Printf("wrote %s\n", path)
			return nil
		},
	}
	c.Flags().IntVar(&offset, "offset", 0, "byte offset")
	c.Flags().IntVar(&length, "length", 1, "length in bytes")
	c.Flags().StringVar(&kind, "kind", "field", "annotation kind")
	c.Flags().StringVar(&label, "label", "", "human label")
	c.Flags().StringVar(&note, "note", "", "free-form note")
	c.Flags().StringVar(&id, "id", "", "stable annotation id (optional)")
	return c
}

func cmdUnannotate() *cobra.Command {
	return &cobra.Command{
		Use:   "unannotate <id>",
		Short: "Remove a human annotation by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			return project.Unannotate(root, args[0])
		},
	}
}

func cmdValidate() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <schema.yaml|schema.json>",
		Short: "Validate a schema AST file (.yaml/.yml/.json)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := schema.LoadFile(args[0], flagSchemaFmt)
			if err != nil {
				return err
			}
			errs := schema.Validate(s)
			if len(errs) == 0 {
				fmt.Println("ok")
				return nil
			}
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "%v\n", e)
			}
			return fmt.Errorf("%w: %d error(s)", wt.ErrSchemaInvalid, len(errs))
		},
	}
}

func cmdSchema() *cobra.Command {
	s := &cobra.Command{Use: "schema", Short: "Schema inference, diff, merge, and export"}
	var outFmt string
	infer := &cobra.Command{
		Use:   "infer [path]",
		Short: "Infer a schema from analysis hypotheses (yaml or json)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
				Budget: budget, ProjectRoot: projectRootForAnalyze(),
			})
			if err != nil {
				return err
			}
			consts := make([]struct {
				Start, End int
				Value      byte
			}, 0, len(res.Constants))
			for _, c := range res.Constants {
				v := byte(0)
				if c.Value != nil {
					v = *c.Value
				}
				consts = append(consts, struct {
					Start, End int
					Value      byte
				}{c.Start, c.End, v})
			}
			sch := schema.InferFromHypotheses(ds.Name, consts, res.Hypotheses)
			format := outFmt
			if format == "" {
				format = flagSchemaFmt
			}
			if strings.ToLower(format) == "json" {
				out, err := schema.MarshalJSON(sch)
				if err != nil {
					return err
				}
				os.Stdout.Write(out)
				fmt.Fprintln(os.Stdout)
				return nil
			}
			out, err := schema.MarshalYAML(sch)
			if err != nil {
				return err
			}
			os.Stdout.Write(out)
			return nil
		},
	}
	infer.Flags().StringVar(&outFmt, "out-format", "", "yaml|json (default yaml)")
	s.AddCommand(infer)
	extendSchemaCommand(s)
	return s
}

func cmdTUI() *cobra.Command {
	return &cobra.Command{
		Use:   "tui [path]",
		Short: "Interactive report browser (hypotheses, entropy, clusters, explain-at)",
		Long:  "Interactive Bubble Tea report browser when stdout is a TTY. Falls back to the stdlib line navigator under NO_COLOR, WIRETAP_TUI=plain, or non-TTY.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
				Budget: budget, ProjectRoot: projectRootForAnalyze(),
			})
			if err != nil {
				return err
			}
			return tui.BrowseReport(os.Stdout, os.Stdin, res, ds)
		},
	}
}

func cmdProject() *cobra.Command {
	p := &cobra.Command{Use: "project", Short: "Manage Wiretap projects"}
	p.AddCommand(&cobra.Command{
		Use:   "init [dir]",
		Short: "Create a new project (wiretap.yaml + samples/ experiments/ annotations/ schemas/ reports/)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			name := filepath.Base(dir)
			if abs, err := filepath.Abs(dir); err == nil {
				name = filepath.Base(abs)
			}
			if err := project.Init(dir, name); err != nil {
				return err
			}
			fmt.Printf("initialized wiretap project in %s\n", dir)
			return nil
		},
	})
	return p
}

func cmdSample() *cobra.Command {
	var labels []string
	var hexStr, name string
	s := &cobra.Command{Use: "sample", Short: "Manage project samples"}
	add := &cobra.Command{
		Use:   "add [file]",
		Short: "Add a sample file (or --hex) with optional --label key=value",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			lm := map[string]string{}
			for _, l := range labels {
				k, v, ok := strings.Cut(l, "=")
				if !ok {
					return fmt.Errorf("%w: label must be key=value (got %q)", wt.ErrInvalidLabel, l)
				}
				lm[k] = v
			}
			if hexStr != "" {
				if name == "" {
					name = "sample.hex"
				}
				path, err := project.AddSampleHex(root, name, hexStr, lm)
				if err != nil {
					return err
				}
				fmt.Printf("added %s\n", path)
				return nil
			}
			if len(args) != 1 {
				return fmt.Errorf("provide a file path or --hex")
			}
			path, err := project.AddSample(root, args[0], lm)
			if err != nil {
				return err
			}
			fmt.Printf("added %s\n", path)
			return nil
		},
	}
	add.Flags().StringArrayVar(&labels, "label", nil, "label as key=value (repeatable)")
	add.Flags().StringVar(&hexStr, "hex", "", "hex payload instead of file")
	add.Flags().StringVar(&name, "name", "", "sample name when using --hex")
	s.AddCommand(add)
	return s
}

func cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Aliases: []string{"ver"},
		Short:   "Print version information",
		Long:    "Prints tool version, commit, and build timestamp (injectable via -ldflags). See also: wiretap about",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("wiretap %s\ncommit %s\nbuilt  %s\ngo     %s\n", wt.Version, wt.Commit, wt.Built, runtimeVersion())
		},
	}
}

func runtimeVersion() string {
	return fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
