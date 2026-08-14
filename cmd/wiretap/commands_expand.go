package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/theworker02/wiretap/internal/analysis"
	"github.com/theworker02/wiretap/internal/project"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func analyzeOpts(budget wt.Budget) wt.AnalyzeOptions {
	cfg := wt.DefaultPassConfig(budget)
	cfg.Jobs = flagJobs
	return wt.AnalyzeOptions{
		Budget:      budget,
		Timeout:     flagTimeout,
		ProjectRoot: projectRootForAnalyze(),
		Config:      &cfg,
	}
}

func hypEnd(h wt.Hypothesis) int {
	if h.Length <= 0 {
		return h.Offset
	}
	return h.Offset + h.Length - 1
}

const rootLongHelp = `Wiretap analyzes authorized binary captures to infer structure, fields, checksums,
and schemas — offline, deterministically, with explainable confidence.

It answers three questions for every finding:
  1. What did you observe?     (measured bytes / stats)
  2. What might it mean?       (competing hypotheses)
  3. Why?                      (evidence for and against)

EXAMPLES
  # Quick look at a hex corpus
  wiretap analyze examples/mystery/captures.hex
  wiretap stats examples/mystery/captures.hex
  wiretap dump examples/mystery/captures.hex --limit 2
  wiretap explain --at field:0 examples/mystery/captures.hex

  # Project workflow
  wiretap project init my-proto && cd my-proto
  wiretap sample add ../captures/a.bin --label mode=idle
  wiretap sample list
  wiretap analyze
  wiretap annotate --offset 0 --length 2 --label magic --kind constant
  wiretap schema infer -o schemas/draft.yaml
  wiretap generate go schemas/draft.yaml -o gen/

  # Differentials & experiments
  wiretap diff --label temp
  wiretap correlate --label temp
  wiretap experiment run

  # Reports & visualization
  wiretap analyze captures.hex --format html -o report.html
  wiretap visualize captures.hex -o map.svg
  wiretap visualize captures.hex --mermaid -o schema.mmd
  wiretap tui captures.hex

  # Tooling
  wiretap doctor
  wiretap passes
  wiretap fingerprint examples/mystery/captures.hex
  wiretap docs architecture
  wiretap completion powershell > wiretap.ps1

SECURITY
  Analyze data you are authorized to study. Acquisition (PCAP drop folders,
  file tails) is separate from inference. No telemetry. Works fully offline.

See also: wiretap docs | wiretap doctor | https://theworker02.github.io/wiretap/
`

func registerCommandGroups(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: "analysis", Title: "Analysis Commands:"},
		&cobra.Group{ID: "project", Title: "Project & Annotation Commands:"},
		&cobra.Group{ID: "schema", Title: "Schema & Codegen Commands:"},
		&cobra.Group{ID: "capture", Title: "Capture & Index Commands:"},
		&cobra.Group{ID: "tooling", Title: "Tooling & Meta Commands:"},
	)
}

func setGroup(c *cobra.Command, id string) *cobra.Command {
	c.GroupID = id
	return c
}

func cmdStats() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:     "stats [path]",
		Aliases: []string{"stat", "byte-stats"},
		Short:   "Print per-offset byte statistics without full inference",
		Long:    "Computes sample count, unique values, entropy, mean/variance, and change frequency per offset. Faster than full analyze — useful for first-pass reconnaissance.",
		Example: `  wiretap stats samples/
  wiretap stats captures.hex --limit 32 --format json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			if ds.Len() == 0 {
				return wt.ErrEmptyDataset
			}
			stats := analysis.ComputeByteStats(ds)
			if limit > 0 && len(stats) > limit {
				stats = stats[:limit]
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"messages":    ds.Len(),
					"fingerprint": ds.Fingerprint(),
					"stats":       stats,
				})
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "OFFSET\tCOUNT\tUNIQ\tENTROPY\tMEAN\tSTDDEV\tCHANGE\tCLASS\n")
			for _, st := range stats {
				class := classifyStat(st)
				fmt.Fprintf(tw, "0x%02X\t%d\t%d\t%.3f\t%.1f\t%.2f\t%.3f\t%s\n",
					st.Offset, st.Count, st.Unique, st.Entropy, st.Mean, st.StdDev, st.ChangeFrequency, class)
			}
			return tw.Flush()
		},
	}
	c.Flags().IntVar(&limit, "limit", 0, "max offsets to print (0 = all)")
	return c
}

func classifyStat(st wt.ByteStat) string {
	if st.Count == 0 {
		return "absent"
	}
	if st.Unique == 1 {
		return "constant"
	}
	if st.Entropy < 1.5 {
		return "low-cardinality"
	}
	if st.Entropy > 6.5 {
		return "high-entropy"
	}
	return "mixed"
}

func cmdSearch() *cobra.Command {
	var hexPat, asciiPat string
	c := &cobra.Command{
		Use:   "search [path]",
		Short: "Find a hex or ASCII byte pattern in capture messages",
		Long:  "Searches every loaded message for a byte pattern. Provide exactly one of --hex or --ascii. Hits include message identity, offset, and surrounding context hex. Use --format json for machine output.",
		Example: `  wiretap search --ascii HTTP examples/mystery/captures.hex
  wiretap search --hex DEADBEEF captures.bin
  wiretap search --hex "de ad be ef" --format json captures.hex`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pattern []byte
			switch {
			case hexPat != "" && asciiPat != "":
				return fmt.Errorf("%w: specify exactly one of --hex or --ascii", wt.ErrInvalidConfig)
			case hexPat != "":
				decoded, err := wt.ParseHex(hexPat)
				if err != nil {
					return err
				}
				pattern = decoded
			case asciiPat != "":
				pattern = []byte(asciiPat)
			default:
				return fmt.Errorf("%w: specify --hex or --ascii", wt.ErrInvalidConfig)
			}
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			if ds.Len() == 0 {
				return wt.ErrEmptyDataset
			}
			hits, err := ds.Search(pattern)
			if err != nil {
				return err
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(hits)
			}
			if len(hits) == 0 {
				fmt.Println("no matches")
				return nil
			}
			for _, hit := range hits {
				fmt.Printf("[%d] id=%s offset=0x%04X len=%d context=%s\n",
					hit.MessageIndex, hit.MessageID, hit.Offset, hit.Length, hit.ContextHex)
			}
			fmt.Printf("%d match(es)\n", len(hits))
			return nil
		},
	}
	c.Flags().StringVar(&hexPat, "hex", "", "hex pattern (spaces, 0x, and colons allowed)")
	c.Flags().StringVar(&asciiPat, "ascii", "", "literal ASCII/UTF-8 pattern")
	return c
}

func cmdDump() *cobra.Command {
	var limit, width, msgIndex int
	c := &cobra.Command{
		Use:     "dump [path]",
		Aliases: []string{"hexdump", "hex"},
		Short:   "Hex-dump messages from a dataset",
		Long:    "Prints classic hex+ASCII dumps. Use --index to select a single message, --limit to cap how many messages are shown.",
		Example: `  wiretap dump captures.hex --limit 3
  wiretap dump samples/ --index 0 --width 16`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			if ds.Len() == 0 {
				return wt.ErrEmptyDataset
			}
			if width <= 0 {
				width = 16
			}
			msgs := ds.Messages
			if msgIndex >= 0 {
				if msgIndex >= len(msgs) {
					return fmt.Errorf("%w: message index %d (have %d)", wt.ErrNotFound, msgIndex, len(msgs))
				}
				msgs = msgs[msgIndex : msgIndex+1]
			} else if limit > 0 && len(msgs) > limit {
				msgs = msgs[:limit]
			}
			for i, m := range msgs {
				fmt.Printf("=== [%d] id=%s len=%d source=%s ===\n", i, m.ID, len(m.Data), m.Source.Kind)
				writeHexDump(os.Stdout, m.Data, width)
				fmt.Println()
			}
			if msgIndex < 0 && limit > 0 && ds.Len() > limit {
				fmt.Printf("… %d more messages (use --limit 0 or --index N)\n", ds.Len()-limit)
			}
			return nil
		},
	}
	c.Flags().IntVar(&limit, "limit", 5, "max messages to dump (0 = all; ignored with --index)")
	c.Flags().IntVar(&width, "width", 16, "bytes per hex row")
	c.Flags().IntVar(&msgIndex, "index", -1, "dump a single message by index")
	return c
}

func writeHexDump(w io.Writer, data []byte, width int) {
	for i := 0; i < len(data); i += width {
		end := i + width
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		hexPart := make([]string, 0, width)
		ascii := make([]byte, 0, width)
		for _, b := range chunk {
			hexPart = append(hexPart, fmt.Sprintf("%02X", b))
			if b >= 32 && b < 127 {
				ascii = append(ascii, b)
			} else {
				ascii = append(ascii, '.')
			}
		}
		for len(hexPart) < width {
			hexPart = append(hexPart, "  ")
		}
		mid := width / 2
		left := strings.Join(hexPart[:mid], " ")
		right := strings.Join(hexPart[mid:], " ")
		fmt.Fprintf(w, "%04X  %s  %s  |%s|\n", i, left, right, string(ascii))
	}
}

func cmdFingerprint() *cobra.Command {
	c := &cobra.Command{
		Use:     "fingerprint [path]",
		Aliases: []string{"fp"},
		Short:   "Print dataset (and optional config) fingerprints for reproducibility",
		Example: `  wiretap fingerprint examples/mystery/captures.hex
  wiretap fingerprint --budget exhaustive samples/`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			opts := analyzeOpts(budget)
			fpPayload := map[string]any{
				"budget":       string(budget),
				"jobs":         flagJobs,
				"max_messages": flagMaxMessages,
				"project":      opts.ProjectRoot,
				"pass_config":  opts.Config,
			}
			out := map[string]any{
				"dataset_name":        ds.Name,
				"messages":            ds.Len(),
				"min_length":          ds.MinLen(),
				"max_length":          ds.MaxLen(),
				"dataset_fingerprint": ds.Fingerprint(),
				"config_fingerprint":  wt.ConfigFingerprint(fpPayload),
				"budget":              string(budget),
				"tool_version":        wt.Version,
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			fmt.Printf("dataset:    %s\n", ds.Name)
			fmt.Printf("messages:   %d  lengths %d..%d\n", ds.Len(), ds.MinLen(), ds.MaxLen())
			fmt.Printf("dataset_fp: %s\n", out["dataset_fingerprint"])
			fmt.Printf("config_fp:  %s\n", out["config_fingerprint"])
			fmt.Printf("budget:     %s\n", budget)
			fmt.Printf("tool:       %s\n", wt.Version)
			return nil
		},
	}
	return c
}

func cmdPasses() *cobra.Command {
	c := &cobra.Command{
		Use:     "passes",
		Aliases: []string{"pass", "plugins"},
		Short:   "List built-in and registered inference passes",
		Long:    "Shows the default analysis pipeline passes and any passes registered via the public plugin API (wt.RegisterPass).",
		RunE: func(cmd *cobra.Command, args []string) error {
			builtin := analysis.DefaultPasses()
			reg := wt.RegisteredPasses()
			if strings.EqualFold(flagFormat, "json") {
				names := make([]string, 0, len(builtin))
				for _, p := range builtin {
					names = append(names, p.Name())
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"builtin":    names,
					"registered": reg,
					"budget":     flagBudget,
				})
			}
			fmt.Println("Built-in pipeline passes:")
			for i, p := range builtin {
				fmt.Printf("  %2d. %s\n", i+1, p.Name())
			}
			fmt.Println()
			fmt.Printf("Registered plugin passes (%d):\n", len(reg))
			if len(reg) == 0 {
				fmt.Println("  (none — see docs/plugins.md and examples/plugins/)")
			} else {
				for _, n := range reg {
					fmt.Printf("  - %s\n", n)
				}
			}
			cfg := wt.DefaultPassConfig(mustBudget())
			fmt.Printf("\nDefault limits for budget=%s: max_candidates=%d max_message_bytes=%d checksum=%v strings=%v\n",
				flagBudget, cfg.MaxCandidates, cfg.MaxMessageBytes, cfg.EnableChecksum, cfg.EnableStrings)
			return nil
		},
	}
	return c
}

func mustBudget() wt.Budget {
	b, err := parseBudget()
	if err != nil {
		return wt.BudgetNormal
	}
	return b
}

func cmdHypotheses() *cobra.Command {
	var kind string
	var minConf float64
	var limit int
	c := &cobra.Command{
		Use:     "hypotheses [path]",
		Aliases: []string{"hyps", "fields"},
		Short:   "List ranked field hypotheses from analysis",
		Long:    "Runs analysis and prints competing field hypotheses. Filter with --kind and --min-confidence.",
		Example: `  wiretap hypotheses captures.hex --kind length
  wiretap hyps captures.hex --min-confidence 0.8 --format json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(cmd.Context(), ds, analyzeOpts(budget))
			if err != nil {
				return err
			}
			hyps := res.Hypotheses
			filtered := hyps[:0]
			for _, h := range hyps {
				if kind != "" && !strings.EqualFold(h.Kind, kind) && !strings.Contains(strings.ToLower(h.Kind), strings.ToLower(kind)) {
					continue
				}
				if h.Confidence.Score < minConf {
					continue
				}
				filtered = append(filtered, h)
			}
			hyps = filtered
			if limit > 0 && len(hyps) > limit {
				hyps = hyps[:limit]
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(hyps)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "ID\tRANGE\tKIND\tSCORE\tDESCRIPTION\n")
			for _, h := range hyps {
				desc := h.Description
				if desc == "" {
					desc = "-"
				}
				if len(desc) > 48 {
					desc = desc[:45] + "..."
				}
				fmt.Fprintf(tw, "%s\t0x%02X..0x%02X\t%s\t%.3f\t%s\n",
					shortID(h.ID), h.Offset, hypEnd(h), h.Kind, h.Confidence.Score, desc)
			}
			_ = tw.Flush()
			fmt.Printf("\n%d hypotheses (of %d total). Use: wiretap explain --id <id> | --at field:N\n", len(hyps), len(res.Hypotheses))
			return nil
		},
	}
	c.Flags().StringVar(&kind, "kind", "", "filter by hypothesis kind substring (length, checksum, counter, …)")
	c.Flags().Float64Var(&minConf, "min-confidence", 0, "minimum confidence score")
	c.Flags().IntVar(&limit, "limit", 50, "max rows to print (0 = all)")
	return c
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func cmdExport() *cobra.Command {
	var outPath, as string
	c := &cobra.Command{
		Use:   "export [path]",
		Short: "Export a dataset as hex lines, JSONL messages, or raw concatenation",
		Long:  "Formats: hex (default), jsonl, bin. Does not run inference — export only.",
		Example: `  wiretap export samples/ -o corpus.hex
  wiretap export captures.hex --as jsonl -o messages.jsonl`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			as = strings.ToLower(as)
			if as == "" {
				as = "hex"
			}
			var b strings.Builder
			switch as {
			case "hex":
				for _, m := range ds.Messages {
					b.WriteString(strings.ToUpper(hex.EncodeToString(m.Data)))
					b.WriteByte('\n')
				}
			case "jsonl":
				for _, m := range ds.Messages {
					row := map[string]any{
						"id":     m.ID,
						"hex":    strings.ToUpper(hex.EncodeToString(m.Data)),
						"len":    len(m.Data),
						"labels": m.Labels,
						"source": m.Source,
					}
					line, err := json.Marshal(row)
					if err != nil {
						return err
					}
					b.Write(line)
					b.WriteByte('\n')
				}
			case "bin":
				// write raw concatenated with no separator — warn in text
				raw := make([]byte, 0)
				for _, m := range ds.Messages {
					raw = append(raw, m.Data...)
				}
				if outPath == "" {
					_, err := os.Stdout.Write(raw)
					return err
				}
				return os.WriteFile(outPath, raw, 0o644)
			default:
				return fmt.Errorf("%w: export --as must be hex|jsonl|bin (got %q)", wt.ErrInvalidConfig, as)
			}
			if outPath == "" {
				_, err := os.Stdout.WriteString(b.String())
				return err
			}
			if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote %s (%d messages, format=%s)\n", outPath, ds.Len(), as)
			return nil
		},
	}
	c.Flags().StringVarP(&outPath, "output", "o", "", "output file (default stdout)")
	c.Flags().StringVar(&as, "as", "hex", "hex|jsonl|bin")
	return c
}

func cmdSummary() *cobra.Command {
	c := &cobra.Command{
		Use:     "summary [path]",
		Aliases: []string{"overview"},
		Short:   "One-page analysis summary (counts, top hypotheses, regions)",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			res, err := wt.Analyze(cmd.Context(), ds, analyzeOpts(budget))
			if err != nil {
				return err
			}
			if strings.EqualFold(flagFormat, "json") {
				top := res.Hypotheses
				if len(top) > 15 {
					top = top[:15]
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"messages":            res.MessageCount,
					"lengths":             []int{res.MinLength, res.MaxLength},
					"dataset_fingerprint": res.DatasetFingerprint,
					"hypothesis_count":    len(res.Hypotheses),
					"constants":           len(res.Constants),
					"regions":             len(res.Regions),
					"warnings":            res.Warnings,
					"top_hypotheses":      top,
					"elapsed_us":          res.ElapsedUS,
				})
			}
			fmt.Println("Wiretap Summary")
			fmt.Printf("  messages:     %d  (len %d..%d)\n", res.MessageCount, res.MinLength, res.MaxLength)
			fmt.Printf("  fingerprint:  %s\n", res.DatasetFingerprint)
			fmt.Printf("  budget:       %s  elapsed: %dµs\n", res.Budget, res.ElapsedUS)
			fmt.Printf("  constants:    %d regions\n", len(res.Constants))
			fmt.Printf("  entropy maps: %d regions\n", len(res.Regions))
			fmt.Printf("  hypotheses:   %d\n", len(res.Hypotheses))
			if len(res.Warnings) > 0 {
				fmt.Printf("  warnings:     %d\n", len(res.Warnings))
			}
			fmt.Println("\nTop hypotheses:")
			n := 10
			if len(res.Hypotheses) < n {
				n = len(res.Hypotheses)
			}
			for i := 0; i < n; i++ {
				h := res.Hypotheses[i]
				fmt.Printf("  %2d. [%.2f] %-16s 0x%02X..0x%02X  %s\n",
					i+1, h.Confidence.Score, h.Kind, h.Offset, hypEnd(h), h.Description)
			}
			fmt.Println("\nNext: wiretap explain --at field:N | wiretap tui | wiretap schema infer")
			return nil
		},
	}
	return c
}

func cmdEnv() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Show Wiretap-related environment variables and defaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := []string{
				"NO_COLOR", "WIRETAP_CACHE_DIR", "WIRETAP_TUI", "WIRETAP_DISABLE_PASSES", "WIRETAP_ENABLE_PASSES",
			}
			fmt.Println("Environment")
			for _, k := range keys {
				v := os.Getenv(k)
				if v == "" {
					v = "(unset)"
				}
				fmt.Printf("  %-24s %s\n", k, v)
			}
			fmt.Println("\nEffective CLI defaults")
			fmt.Printf("  format=%s budget=%s color=%v jobs=%d max-messages=%d\n",
				flagFormat, flagBudget, flagColor, flagJobs, flagMaxMessages)
			fmt.Printf("  go=%s os=%s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

func cmdAbout() *cobra.Command {
	return &cobra.Command{
		Use:     "about",
		Aliases: []string{"info"},
		Short:   "About Wiretap: version, license posture, and design principles",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf(`Wiretap %s
Commit:  %s
Built:   %s
Go:      %s
OS/Arch: %s/%s

Wiretap — independent tooling for authorized binary protocol analysis.
Maintained by @theworker02. Evidence-backed inference. Offline by default. No telemetry. No LLM APIs.

Principles:
  • Observation ≠ hypothesis ≠ confidence ≠ evidence
  • Prefer "Unknown" / "Insufficient evidence" over unsupported guesses
  • Human annotations are trusted and never auto-overwritten
  • Acquisition is separate from analysis

Docs:     wiretap docs | wiretap catalog
Site:     https://theworker02.github.io/wiretap/
Repo:     https://github.com/theworker02/wiretap
Sponsor:  https://github.com/sponsors/theworker02
thanks.dev https://thanks.dev/u/gh/theworker02
License:  see LICENSE
`, wt.Version, wt.Commit, wt.Built, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

func cmdConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show effective analysis configuration for the current flags/budget",
		RunE: func(cmd *cobra.Command, args []string) error {
			budget, err := parseBudget()
			if err != nil {
				return err
			}
			cfg := wt.DefaultPassConfig(budget)
			cfg.Jobs = flagJobs
			root := projectRootForAnalyze()
			fp := wt.ConfigFingerprint(map[string]any{
				"budget": string(budget), "jobs": flagJobs, "max_messages": flagMaxMessages,
				"project": root, "pass_config": cfg,
			})
			out := map[string]any{
				"budget":             string(budget),
				"format":             flagFormat,
				"project":            root,
				"max_messages":       flagMaxMessages,
				"jobs":               flagJobs,
				"timeout":            flagTimeout.String(),
				"pass_config":        cfg,
				"config_fingerprint": fp,
				"registered_passes":  wt.RegisteredPasses(),
				"builtin_pass_count": len(analysis.DefaultPasses()),
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			fmt.Printf("budget:           %s\n", budget)
			fmt.Printf("format:           %s\n", flagFormat)
			fmt.Printf("project:          %s\n", map[bool]string{true: root, false: "(none)"}[root != ""])
			fmt.Printf("max-messages:     %d\n", flagMaxMessages)
			fmt.Printf("jobs:             %d\n", flagJobs)
			fmt.Printf("timeout:          %s\n", flagTimeout)
			fmt.Printf("max_candidates:   %d\n", cfg.MaxCandidates)
			fmt.Printf("max_msg_bytes:    %d\n", cfg.MaxMessageBytes)
			fmt.Printf("checksum:         %v  strings: %v  timestamps: %v\n", cfg.EnableChecksum, cfg.EnableStrings, cfg.EnableTimestamps)
			fmt.Printf("config_fp:        %s\n", out["config_fingerprint"])
			return nil
		},
	}
}

func cmdInitAlias() *cobra.Command {
	return &cobra.Command{
		Use:     "init [dir]",
		Aliases: []string{"new"},
		Short:   "Alias for 'project init' — create a Wiretap project",
		Args:    cobra.MaximumNArgs(1),
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
			fmt.Println("next: wiretap sample add <file> --label key=value && wiretap analyze")
			return nil
		},
	}
}

func cmdHelpAll() *cobra.Command {
	return &cobra.Command{
		Use:    "help-all",
		Short:  "Print help for every command (useful for docs generation)",
		Hidden: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			var names []string
			for _, c := range root.Commands() {
				if !c.IsAvailableCommand() || c.Hidden {
					continue
				}
				names = append(names, c.Name())
			}
			sort.Strings(names)
			for _, name := range names {
				c, _, err := root.Find([]string{name})
				if err != nil {
					continue
				}
				fmt.Printf("\n======== wiretap %s ========\n", name)
				_ = c.Help()
			}
			return nil
		},
	}
}

func cmdStrings() *cobra.Command {
	return &cobra.Command{
		Use:   "strings [path]",
		Short: "Show string-related hypotheses only (ASCII/UTF/length-prefixed candidates)",
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
			res, err := wt.Analyze(context.Background(), ds, analyzeOpts(budget))
			if err != nil {
				return err
			}
			var hyps []wt.Hypothesis
			for _, h := range res.Hypotheses {
				k := strings.ToLower(h.Kind)
				if strings.Contains(k, "string") || strings.Contains(k, "ascii") || strings.Contains(k, "utf") {
					hyps = append(hyps, h)
				}
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(hyps)
			}
			if len(hyps) == 0 {
				fmt.Println("No string hypotheses (Insufficient evidence).")
				return nil
			}
			for _, h := range hyps {
				fmt.Printf("[%.2f] %s  0x%02X..0x%02X  %s\n", h.Confidence.Score, h.Kind, h.Offset, hypEnd(h), h.Description)
			}
			return nil
		},
	}
}

func cmdTimestamps() *cobra.Command {
	return &cobra.Command{
		Use:   "timestamps [path]",
		Short: "Show timestamp-related hypotheses only",
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
			res, err := wt.Analyze(context.Background(), ds, analyzeOpts(budget))
			if err != nil {
				return err
			}
			var hyps []wt.Hypothesis
			for _, h := range res.Hypotheses {
				k := strings.ToLower(h.Kind)
				if strings.Contains(k, "time") || strings.Contains(k, "epoch") {
					hyps = append(hyps, h)
				}
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(hyps)
			}
			if len(hyps) == 0 {
				fmt.Println("No timestamp hypotheses (Insufficient evidence).")
				return nil
			}
			for _, h := range hyps {
				fmt.Printf("[%.2f] %s  0x%02X..0x%02X  %s\n", h.Confidence.Score, h.Kind, h.Offset, hypEnd(h), h.Description)
			}
			return nil
		},
	}
}

func expandProjectCommand(p *cobra.Command) {
	p.Short = "Manage Wiretap projects (init, status, info, tree)"
	p.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show project root, config, and directory counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			cfg, err := project.LoadConfig(root)
			if err != nil {
				return err
			}
			tree, err := project.Tree(root)
			if err != nil {
				return err
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"root": root, "config": cfg, "tree": tree})
			}
			fmt.Printf("project:  %s\n", cfg.Name)
			fmt.Printf("root:     %s\n", root)
			fmt.Printf("created:  %s\n", cfg.CreatedAt)
			if cfg.Description != "" {
				fmt.Printf("about:    %s\n", cfg.Description)
			}
			keys := make([]string, 0, len(tree))
			for k := range tree {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Println("layout:")
			for _, k := range keys {
				fmt.Printf("  %-14s %d\n", k+"/", tree[k])
			}
			return nil
		},
	})
	p.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print the project root path",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			fmt.Println(root)
			return nil
		},
	})
	p.AddCommand(&cobra.Command{
		Use:   "tree",
		Short: "Print project directory tree with file counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			tree, err := project.Tree(root)
			if err != nil {
				return err
			}
			fmt.Println(root)
			keys := make([]string, 0, len(tree))
			for k := range tree {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("├── %s/ (%d)\n", k, tree[k])
			}
			fmt.Println("└── wiretap.yaml")
			return nil
		},
	})
	p.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Alias for project status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.Commands()[len(p.Commands())-1].RunE(cmd, args) // fallback
		},
	})
	// Fix info to call status properly
	for _, c := range p.Commands() {
		if c.Use == "info" {
			c.RunE = func(cmd *cobra.Command, args []string) error {
				for _, s := range p.Commands() {
					if s.Name() == "status" {
						return s.RunE(cmd, args)
					}
				}
				return fmt.Errorf("status command missing")
			}
		}
	}
}

func expandSampleCommand(s *cobra.Command) {
	s.Short = "Manage project samples (add, list, show, rm, label)"
	s.AddCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List samples and labels in the current project",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			items, err := project.ListSamples(root)
			if err != nil {
				return err
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(items)
			}
			if len(items) == 0 {
				fmt.Println("(no samples — wiretap sample add <file>)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "NAME\tBYTES\tLABELS\n")
			for _, it := range items {
				labs := formatLabels(it.Labels)
				fmt.Fprintf(tw, "%s\t%d\t%s\n", it.Name, it.Bytes, labs)
			}
			return tw.Flush()
		},
	})
	s.AddCommand(&cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a sample and its labels sidecar",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			if err := project.RemoveSample(root, args[0]); err != nil {
				return err
			}
			fmt.Printf("removed %s\n", filepath.Base(args[0]))
			return nil
		},
	})
	s.AddCommand(&cobra.Command{
		Use:   "show <name>",
		Short: "Show sample metadata and a short hex preview",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			items, err := project.ListSamples(root)
			if err != nil {
				return err
			}
			base := filepath.Base(args[0])
			var found *project.SampleInfo
			for i := range items {
				if items[i].Name == base {
					found = &items[i]
					break
				}
			}
			if found == nil {
				return fmt.Errorf("%w: sample %s", wt.ErrNotFound, base)
			}
			data, err := os.ReadFile(found.Path)
			if err != nil {
				return err
			}
			preview := data
			if len(preview) > 64 {
				preview = preview[:64]
			}
			fmt.Printf("name:   %s\n", found.Name)
			fmt.Printf("path:   %s\n", found.Path)
			fmt.Printf("bytes:  %d\n", found.Bytes)
			fmt.Printf("labels: %s\n", formatLabels(found.Labels))
			fmt.Printf("preview:%s\n", strings.ToUpper(hex.EncodeToString(preview)))
			if int64(len(data)) > found.Bytes && found.Bytes == 0 {
				// no-op; Bytes from stat
			}
			if len(data) > 64 {
				fmt.Printf("        … (%d more bytes)\n", len(data)-64)
			}
			return nil
		},
	})
	var labels []string
	labelCmd := &cobra.Command{
		Use:   "label <name>",
		Short: "Add/merge labels on an existing sample (--label key=value)",
		Args:  cobra.ExactArgs(1),
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
			if len(lm) == 0 {
				return fmt.Errorf("provide at least one --label key=value")
			}
			if err := project.SetSampleLabels(root, args[0], lm); err != nil {
				return err
			}
			fmt.Printf("updated labels on %s\n", filepath.Base(args[0]))
			return nil
		},
	}
	labelCmd.Flags().StringArrayVar(&labels, "label", nil, "label as key=value (repeatable)")
	s.AddCommand(labelCmd)
}

func formatLabels(m map[string]string) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

func expandAnnotateCommand(c *cobra.Command) {
	c.Short = "Add or list human annotations (never auto-overwritten)"
	c.Example = `  wiretap annotate --offset 0 --length 1 --label magic --kind constant
  wiretap annotate list
  wiretap unannotate ann_123`
	c.AddCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List project annotations",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := project.FindRoot(".")
			if err != nil {
				return err
			}
			anns, err := project.ListAnnotations(root)
			if err != nil {
				return err
			}
			if strings.EqualFold(flagFormat, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(anns)
			}
			if len(anns) == 0 {
				fmt.Println("(no annotations)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "ID\tOFFSET\tLEN\tKIND\tLABEL\tNOTE\n")
			for _, a := range anns {
				fmt.Fprintf(tw, "%s\t0x%02X\t%d\t%s\t%s\t%s\n", a.ID, a.Offset, a.Length, a.Kind, a.Label, a.Note)
			}
			return tw.Flush()
		},
	})
}

func cmdBenchInfo() *cobra.Command {
	return &cobra.Command{
		Use:   "bench-info",
		Short: "Describe bundled benchmark datasets under testdata/bench",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "testdata/bench"
			entries, err := os.ReadDir(dir)
			if err != nil {
				fmt.Println("testdata/bench not found (run from repo root). Use: go test -bench=. ./...")
				return nil
			}
			fmt.Println("Benchmark datasets:")
			for _, e := range entries {
				if e.IsDir() {
					fmt.Printf("  - %s/\n", e.Name())
				}
			}
			fmt.Println("\nRun: make bench   or   go test -bench=. ./...")
			return nil
		},
	}
}

func cmdNow() *cobra.Command {
	// tiny utility sometimes useful in scripts / demos
	return &cobra.Command{
		Use:    "time",
		Short:  "Print UTC timestamp (scripting helper)",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(time.Now().UTC().Format(time.RFC3339Nano))
		},
	}
}
