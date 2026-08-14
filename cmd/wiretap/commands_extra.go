package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/theworker02/wiretap/internal/capture"
	"github.com/theworker02/wiretap/internal/compare"
	wteval "github.com/theworker02/wiretap/internal/eval"
	"github.com/theworker02/wiretap/internal/index"
	"github.com/theworker02/wiretap/internal/project"
	"github.com/theworker02/wiretap/internal/visualize"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

func cmdIndex() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "index [path]",
		Short: "Build an on-disk sample index for incremental analyze",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			idx := index.Build(ds)
			path := out
			if path == "" {
				root := projectRootForAnalyze()
				if root != "" {
					path = index.DefaultPath(root)
				} else {
					path = "reports/index.json"
				}
			}
			var prev *index.Index
			if old, err := index.Load(path); err == nil {
				prev = old
			}
			d := index.Diff(prev, idx)
			if err := index.Save(idx, path); err != nil {
				return err
			}
			fmt.Printf("wrote %s entries=%d new=%d changed=%d unchanged=%d\n",
				path, len(idx.Entries), len(d.New), len(d.Changed), len(d.Unchanged))
			fmt.Printf("needs_analyze=%v fingerprint=%s\n", index.NeedsAnalyze(prev, idx), idx.Fingerprint)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "index path (default reports/index.json)")
	return c
}

func cmdVisualize() *cobra.Command {
	var out, schemaPath string
	var useSchema, useReport, mermaid, graphviz bool
	c := &cobra.Command{
		Use:   "visualize [path]",
		Short: "Generate SVG/HTML/Mermaid/Graphviz field map from report and/or schema",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				if mermaid {
					out = "schema.mmd"
				} else if graphviz {
					out = "schema.dot"
				} else {
					out = "map.svg"
				}
			}
			var sch *schema.Schema
			var res *wt.Result
			if schemaPath != "" || useSchema {
				p := schemaPath
				if p == "" && len(args) == 1 && (strings.HasSuffix(args[0], ".yaml") || strings.HasSuffix(args[0], ".yml") || strings.HasSuffix(args[0], ".json")) {
					p = args[0]
				}
				if p == "" {
					return fmt.Errorf("%w: --schema path required", wt.ErrInvalidConfig)
				}
				var err error
				sch, err = schema.LoadFile(p, flagSchemaFmt)
				if err != nil {
					return err
				}
			}
			if !useSchema || useReport || sch == nil {
				ds, err := loadDataset(args)
				if err != nil && sch == nil {
					return err
				}
				if err == nil {
					budget, err := parseBudget()
					if err != nil {
						return err
					}
					res, err = wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
						Budget: budget, ProjectRoot: projectRootForAnalyze(),
					})
					if err != nil {
						return err
					}
				}
			}
			lower := strings.ToLower(out)
			switch {
			case mermaid || strings.HasSuffix(lower, ".mmd"):
				if err := visualize.WriteMermaid(out, res, sch); err != nil {
					return err
				}
			case graphviz || strings.HasSuffix(lower, ".dot"):
				dot, err := visualize.RenderGraphvizDOT(res, sch)
				if err != nil {
					return err
				}
				if err := os.WriteFile(out, []byte(dot), 0o644); err != nil {
					return err
				}
			default:
				if err := visualize.WriteFile(out, res, sch, visualize.Options{Title: "Wiretap field map"}); err != nil {
					return err
				}
			}
			fmt.Printf("wrote %s\n", out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output .svg/.html/.mmd/.dot (default map.svg)")
	c.Flags().StringVar(&schemaPath, "schema", "", "schema file")
	c.Flags().BoolVar(&useSchema, "from-schema", false, "prefer schema for lanes")
	c.Flags().BoolVar(&useReport, "from-report", false, "also include analyze report hypotheses")
	c.Flags().BoolVar(&mermaid, "mermaid", false, "emit Mermaid flowchart (.mmd)")
	c.Flags().BoolVar(&graphviz, "graphviz", false, "emit Graphviz DOT")
	return c
}

func cmdWatch() *cobra.Command {
	var once, analyze bool
	var out string
	c := &cobra.Command{
		Use:   "watch <dir>",
		Short: "Ingest authorized captures from a drop folder (acquisition ≠ analysis)",
		Long:  "Scans a directory for .bin/.hex/.pcap/.pcapng files you are authorized to study. Does not tap networks, MITM, or bypass access controls. With --analyze, writes an incremental JSON report.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := capture.WatchDir(args[0], capture.WatchOptions{Once: once || true, LoadOptions: capture.LoadOptions{MaxMessages: flagMaxMessages}})
			if err != nil {
				return err
			}
			fmt.Printf("loaded %d messages from %s (authorized drop-folder ingest)\n", ds.Len(), args[0])
			if !analyze {
				for i, m := range ds.Messages {
					if i >= 10 {
						fmt.Printf("… %d more\n", ds.Len()-10)
						break
					}
					fmt.Printf("  %s len=%d\n", m.ID, len(m.Data))
				}
				return nil
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{Budget: budget, Progress: progressReporter()})
			if err != nil {
				return err
			}
			saveLastReport(res)
			path := out
			if path == "" {
				root := projectRootForAnalyze()
				if root != "" {
					path = filepath.Join(root, "reports", "watch.json")
				} else {
					path = "reports/watch.json"
				}
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
				return err
			}
			raw, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Printf("hypotheses=%d elapsed_ms=%d elapsed_us=%d wrote %s\n", len(res.Hypotheses), res.ElapsedMS, res.ElapsedUS, path)
			return nil
		},
	}
	c.Flags().BoolVar(&once, "once", true, "single scan (default)")
	c.Flags().BoolVar(&analyze, "analyze", false, "run analyze after ingest")
	c.Flags().StringVarP(&out, "out", "o", "", "incremental JSON report path")
	return c
}

func cmdCapture() *cobra.Command {
	var fromDir, pcapPath string
	var analyze, follow bool
	var followIdle time.Duration
	c := &cobra.Command{
		Use:   "capture",
		Short: "Authorized local capture ingest (drop-folder / pcap file-tail)",
		Long:  "SAFETY: authorized use only. No MITM, no credential bypass, no remote exploit helpers, no Npcap live sniffing. Acquisition is separate from analysis. Use --from-dir for drop folders or --pcap [--follow] to load/tail an operator-provided PCAP file as it grows.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromDir == "" && pcapPath == "" {
				return fmt.Errorf("%w: require --from-dir and/or --pcap", wt.ErrInvalidConfig)
			}
			var ds *wt.Dataset
			var err error
			switch {
			case pcapPath != "" && follow:
				ctx := context.Background()
				ds, err = capture.FollowPCAP(ctx, pcapPath, capture.FollowPCAPOptions{
					LoadOptions: capture.LoadOptions{MaxMessages: flagMaxMessages},
					IdleTimeout: followIdle,
				})
				if err != nil {
					return err
				}
				fmt.Printf("pcap follow ingest: %d messages from %s (authorized file-tail; not live sniffing)\n", ds.Len(), pcapPath)
			case pcapPath != "":
				ds, err = capture.ImportPCAP(pcapPath, capture.LoadOptions{MaxMessages: flagMaxMessages})
				if err != nil {
					return err
				}
				fmt.Printf("pcap ingest: %d messages from %s\n", ds.Len(), pcapPath)
			default:
				ds, err = capture.LoadDropDir(fromDir, capture.LoadOptions{MaxMessages: flagMaxMessages})
				if err != nil {
					return err
				}
				fmt.Printf("capture ingest: %d messages from %s\n", ds.Len(), fromDir)
			}
			if fromDir != "" && pcapPath != "" {
				fmt.Println("note: when both --pcap and --from-dir are set, --pcap wins")
			}
			if !analyze {
				return nil
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{Budget: budget})
			if err != nil {
				return err
			}
			fmt.Printf("analyze: hypotheses=%d elapsed_us=%d\n", len(res.Hypotheses), res.ElapsedUS)
			return nil
		},
	}
	c.Flags().StringVar(&fromDir, "from-dir", "", "drop folder of authorized captures")
	c.Flags().StringVar(&pcapPath, "pcap", "", "authorized PCAP file to ingest (classic pcap)")
	c.Flags().BoolVar(&follow, "follow", false, "tail a growing PCAP file (file follow; not interface sniffing)")
	c.Flags().DurationVar(&followIdle, "follow-idle", 2*time.Second, "stop follow after this much idle growth")
	c.Flags().BoolVar(&analyze, "analyze", false, "run analysis after ingest")
	return c
}

func cmdExperiment() *cobra.Command {
	exp := &cobra.Command{Use: "experiment", Short: "Differential experiments 2.0"}
	var label string
	run := &cobra.Command{
		Use:   "run [path]",
		Short: "Multi-label ablation: which offsets explain label variance",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			root := projectRootForAnalyze()
			if root != "" {
				_ = os.MkdirAll(filepath.Join(root, "experiments"), 0o755)
			}
			keys := ds.LabelKeys()
			if label != "" {
				keys = []string{label}
			}
			if len(keys) == 0 {
				return fmt.Errorf("%w: no labels on dataset; add --label key=value samples", wt.ErrInvalidLabel)
			}
			report := map[string]any{
				"kind":    "experiment_ablation",
				"notes":   "measured partial-dependence style byte variance by label; not causal proof",
				"labels":  keys,
				"results": []any{},
			}
			results := []any{}
			for _, k := range keys {
				vals := map[string]int{}
				for _, m := range ds.Messages {
					vals[m.Labels[k]]++
				}
				var cohorts []string
				for v := range vals {
					if v != "" {
						cohorts = append(cohorts, v)
					}
				}
				if len(cohorts) < 2 {
					continue
				}
				// pairwise first two cohorts for diff + correlate
				a, b := cohorts[0], cohorts[1]
				diff, err := compare.Diff(ds, k, a, b)
				if err != nil {
					continue
				}
				corr, _ := compare.CorrelateNumeric(ds, k, 0)
				ablation := []map[string]any{}
				for _, r := range diff.Changed {
					ablation = append(ablation, map[string]any{
						"start": r.Start, "end": r.End, "confidence": r.Confidence.Level,
					})
				}
				results = append(results, map[string]any{
					"label": k, "cohort_a": a, "cohort_b": b,
					"changed_regions": ablation, "correlations": corr,
				})
			}
			report["results"] = results
			if root != "" {
				path := filepath.Join(root, "experiments", fmt.Sprintf("run_%d.json", time.Now().Unix()))
				raw, _ := json.MarshalIndent(report, "", "  ")
				_ = os.WriteFile(path, raw, 0o644)
				fmt.Printf("wrote %s\n", path)
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		},
	}
	run.Flags().StringVar(&label, "label", "", "focus on one label key")
	exp.AddCommand(run)
	return exp
}

func extendSchemaCommand(s *cobra.Command) {
	s.AddCommand(&cobra.Command{
		Use:   "fmt [schema]",
		Short: "Canonical-format a schema file (YAML or JSON)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := schema.LoadFile(args[0], flagSchemaFmt)
			if err != nil {
				return err
			}
			out, err := schema.FormatCanonical(s, args[0], flagSchemaFmt)
			if err != nil {
				return err
			}
			return os.WriteFile(args[0], out, 0o644)
		},
	})
	s.AddCommand(&cobra.Command{
		Use:   "diff <a> <b>",
		Short: "Diff two schema files",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := schema.LoadFile(args[0], flagSchemaFmt)
			if err != nil {
				return err
			}
			b, err := schema.LoadFile(args[1], flagSchemaFmt)
			if err != nil {
				return err
			}
			d := schema.Diff(a, b)
			if strings.ToLower(flagFormat) == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(d)
			}
			fmt.Print(schema.FormatDiff(d))
			return nil
		},
	})
	s.AddCommand(&cobra.Command{
		Use:   "merge [path]",
		Short: "Merge project annotations into an inferred schema",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := projectRootForAnalyze()
			if root == "" {
				return fmt.Errorf("%w: not in a wiretap project", wt.ErrInvalidConfig)
			}
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{Budget: budget, ProjectRoot: root})
			if err != nil {
				return err
			}
			consts := make([]struct {
				Start, End int
				Value      byte
			}, 0)
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
			anns, _ := project.ListAnnotations(root)
			overlays := make([]schema.AnnOverlay, 0, len(anns))
			for _, a := range anns {
				overlays = append(overlays, schema.AnnOverlay{
					Offset: a.Offset, Length: a.Length, Kind: a.Kind, Label: a.Label, Note: a.Note,
				})
			}
			merged := schema.MergeAnnotations(sch, overlays)
			out, err := schema.MarshalYAML(merged)
			if err != nil {
				return err
			}
			os.Stdout.Write(out)
			return nil
		},
	})
	s.AddCommand(&cobra.Command{
		Use:   "edit",
		Short: "Annotate → infer → diff loop helper (prints next steps)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(`Wiretap schema edit loop (interactive workflow):
  1. wiretap annotate --offset N --length L --label NAME
  2. wiretap schema infer > schemas/draft.yaml
  3. wiretap schema merge > schemas/merged.yaml
  4. wiretap schema diff schemas/draft.yaml schemas/merged.yaml
  5. wiretap validate schemas/merged.yaml
  6. wiretap lint schemas/merged.yaml
Annotations are trusted evidence and never auto-overwritten.`)
			return nil
		},
	})
	s.AddCommand(&cobra.Command{
		Use:   "lint <schema>",
		Short: "Lint schema hygiene (overlaps, endian, unnamed fields)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdLint().RunE(cmd, args)
		},
	})
}

func wrapGenerate() *cobra.Command {
	var pkg, out, target string
	c := &cobra.Command{
		Use:   "generate [kaitai|wireshark|go] <schema>",
		Short: "Generate Go / Kaitai Struct / Wireshark Lua from a schema",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			schemaPath := args[0]
			lang := "go"
			if len(args) == 2 {
				lang = strings.ToLower(args[0])
				schemaPath = args[1]
			} else if target != "" {
				lang = strings.ToLower(target)
			}
			s, err := schema.LoadFile(schemaPath, flagSchemaFmt)
			if err != nil {
				return err
			}
			if errs := schema.Validate(s); len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "%v\n", e)
				}
				return fmt.Errorf("%w: fix schema before generate", wt.ErrSchemaInvalid)
			}
			var code string
			switch lang {
			case "go", "":
				code, err = schema.GenerateGo(s, pkg)
			case "kaitai", "ksy":
				code, err = schema.GenerateKaitai(s)
			case "wireshark", "lua":
				code, err = schema.GenerateWiresharkLua(s, pkg)
			default:
				return fmt.Errorf("%w: language must be go|kaitai|wireshark", wt.ErrInvalidConfig)
			}
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				fmt.Print(code)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && filepath.Dir(out) != "." {
				return err
			}
			return os.WriteFile(out, []byte(code), 0o644)
		},
	}
	c.Flags().StringVar(&pkg, "package", "protocol", "Go package name or Wireshark proto id")
	c.Flags().StringVarP(&out, "out", "o", "-", "output file (default stdout)")
	c.Flags().StringVar(&target, "lang", "", "go|kaitai|wireshark (alternative to positional)")
	return c
}

func wrapEval() *cobra.Command {
	var seed int64
	var n int
	var format string
	c := &cobra.Command{
		Use:   "eval",
		Short: "Run synthetic protocol evaluation and print measured metrics",
		Long:  "Generates a deterministic synthetic corpus with ground truth and reports measured precision/recall — never invented accuracy numbers. Default budget=normal.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format == "" {
				format = flagFormat
			}
			budget := flagBudget
			if budget == "" {
				budget = "normal"
			}
			return wteval.RunEvalOpts(os.Stdout, wteval.EvalOptions{
				Seed: seed, N: n, Budget: budget, Format: format,
				ProjectRoot: projectRootForAnalyze(),
			})
		},
	}
	c.Flags().Int64Var(&seed, "seed", 1, "RNG seed")
	c.Flags().IntVar(&n, "n", 50, "message count")
	c.Flags().StringVar(&format, "eval-format", "", "text|json|markdown (default --format)")
	return c
}
