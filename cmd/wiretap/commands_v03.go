package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/theworker02/wiretap/internal/analysis"
	"github.com/theworker02/wiretap/internal/project"
	"github.com/theworker02/wiretap/internal/report"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

func cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Health-check Go version, layout, samples, cache, and passes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ok := true
			check := func(name string, pass bool, detail string) {
				status := "ok"
				if !pass {
					status = "FAIL"
					ok = false
				}
				fmt.Printf("%-18s %-4s  %s\n", name, status, detail)
			}

			ver := runtime.Version()
			check("go_version", true, ver+" (need go1.23+)")

			wd, _ := os.Getwd()
			root, err := project.FindRoot(wd)
			if err != nil {
				check("project", true, "no wiretap.yaml here (optional)")
			} else {
				cfg, _ := project.LoadConfig(root)
				name := root
				if cfg != nil {
					name = cfg.Name
				}
				check("project", true, name)
				samples := 0
				if ds, err := project.LoadSamples(root); err == nil {
					samples = ds.Len()
				}
				check("samples", samples > 0 || true, fmt.Sprintf("%d messages in samples/", samples))
				anns, _ := project.ListAnnotations(root)
				notes, _ := project.ListNotes(root)
				check("annotations", true, fmt.Sprintf("%d", len(anns)))
				check("notes", true, fmt.Sprintf("%d", len(notes)))
			}

			cache := os.Getenv("WIRETAP_CACHE_DIR")
			if cache == "" {
				cache = filepath.Join(os.TempDir(), "wiretap-cache")
				check("cache_dir", true, "WIRETAP_CACHE_DIR unset; default would be "+cache)
			} else {
				_ = os.MkdirAll(cache, 0o755)
				st, err := os.Stat(cache)
				check("cache_dir", err == nil && st.IsDir(), cache)
			}

			passes := analysis.DefaultPasses()
			names := make([]string, 0, len(passes))
			for _, p := range passes {
				names = append(names, p.Name())
			}
			check("builtin_passes", len(passes) > 0, strings.Join(names, ", "))
			reg := wt.RegisteredPasses()
			check("registered_plugins", true, fmt.Sprintf("%d: %s", len(reg), strings.Join(reg, ", ")))

			check("tool_version", wt.Version != "", wt.Version+" commit="+wt.Commit)

			// Layout hints when running from the Wiretap repo checkout.
			for _, p := range []string{"examples/mystery", "docs", "schema", "pkg/wiretap"} {
				_, err := os.Stat(p)
				check("layout:"+p, err == nil || root != "", map[bool]string{true: "present", false: "missing (ok outside repo)"}[err == nil])
			}

			if !ok {
				return fmt.Errorf("doctor found problems")
			}
			fmt.Println("doctor: all checks passed")
			return nil
		},
	}
}

func cmdDocs() *cobra.Command {
	c := &cobra.Command{
		Use:   "docs [topic]",
		Short: "Print local documentation topics",
		Long: "Topics: architecture, brand, plugins, capture-ethics, generators, visualization, eval, mystery-tutorial, tui, wireshark, windows, index.\n" +
			"A browsable GitHub Pages site (when published) is built from docs-site/ in this repository.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			topic := "index"
			if len(args) == 1 {
				topic = strings.TrimSpace(strings.ToLower(args[0]))
			}
			path, err := resolveDocTopic(topic)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			os.Stdout.Write(b)
			if !strings.HasSuffix(string(b), "\n") {
				fmt.Println()
			}
			return nil
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return []string{
				"index", "architecture", "brand", "plugins", "capture-ethics", "generators",
				"visualization", "eval", "mystery-tutorial", "tui", "wireshark", "windows", "readme",
			}, cobra.ShellCompDirectiveNoFileComp
		},
	}
	return c
}

func resolveDocTopic(topic string) (string, error) {
	topic = strings.TrimPrefix(topic, "docs/")
	topic = strings.TrimSuffix(topic, ".md")
	candidates := map[string][]string{
		"index":            {"docs/README.md"},
		"readme":           {"README.md", "docs/README.md"},
		"architecture":     {"docs/architecture.md"},
		"brand":            {"docs/brand.md"},
		"branding":         {"docs/brand.md"},
		"plugins":          {"docs/plugins.md"},
		"capture-ethics":   {"docs/capture-ethics.md"},
		"ethics":           {"docs/capture-ethics.md"},
		"generators":       {"docs/generators.md"},
		"kaitai":           {"docs/generators.md"},
		"visualization":    {"docs/visualization.md"},
		"visualize":        {"docs/visualization.md"},
		"eval":             {"docs/eval.md"},
		"mystery-tutorial": {"docs/mystery-tutorial.md"},
		"mystery":          {"docs/mystery-tutorial.md"},
		"tui":              {"docs/tui.md"},
		"wireshark":        {"docs/wireshark.md"},
		"windows":          {"docs/windows.md"},
	}
	paths, ok := candidates[topic]
	if !ok {
		return "", fmt.Errorf("%w: unknown docs topic %q (try: wiretap docs index)", wt.ErrInvalidConfig, topic)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	// Search upward from cwd for repo docs.
	wd, _ := os.Getwd()
	dir := wd
	for i := 0; i < 8; i++ {
		for _, p := range paths {
			full := filepath.Join(dir, p)
			if _, err := os.Stat(full); err == nil {
				return full, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("%w: docs file for %q not found (run from Wiretap checkout)", wt.ErrNotFound, topic)
}

func cmdCompletion() *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion scripts",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch strings.ToLower(args[0]) {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("%w: shell must be bash|zsh|fish|powershell", wt.ErrInvalidConfig)
			}
		},
	}
}

func cmdNote() *cobra.Command {
	var list bool
	var search string
	c := &cobra.Command{
		Use:   "note [offset] [text...]",
		Short: "Project-local research notes (separate from annotations)",
		Long:  "Examples:\n  wiretap note 0x04 \"device id?\"\n  wiretap note --list\n  wiretap note --search device",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := projectRootForAnalyze()
			if root == "" {
				return fmt.Errorf("%w: notes require a wiretap project (wiretap.yaml)", wt.ErrNoProject)
			}
			if list {
				notes, err := project.ListNotes(root)
				if err != nil {
					return err
				}
				if len(notes) == 0 {
					fmt.Println("(no notes)")
					return nil
				}
				for _, n := range notes {
					off := "-"
					if n.Offset != nil {
						off = fmt.Sprintf("0x%x", *n.Offset)
					}
					fmt.Printf("%s  off=%s  %s\n", n.ID, off, n.Text)
				}
				return nil
			}
			if search != "" {
				notes, err := project.SearchNotes(root, search)
				if err != nil {
					return err
				}
				for _, n := range notes {
					off := "-"
					if n.Offset != nil {
						off = fmt.Sprintf("0x%x", *n.Offset)
					}
					fmt.Printf("%s  off=%s  %s\n", n.ID, off, n.Text)
				}
				return nil
			}
			if len(args) == 0 {
				return fmt.Errorf("%w: provide offset + text, or --list / --search", wt.ErrInvalidConfig)
			}
			var offset *int
			textArgs := args
			if v, err := parseOffsetArg(args[0]); err == nil {
				offset = &v
				textArgs = args[1:]
			}
			text := strings.TrimSpace(strings.Join(textArgs, " "))
			n, path, err := project.AddNote(root, offset, text)
			if err != nil {
				return err
			}
			fmt.Printf("wrote %s id=%s\n", path, n.ID)
			return nil
		},
	}
	c.Flags().BoolVar(&list, "list", false, "list notes")
	c.Flags().StringVar(&search, "search", "", "search note text")
	return c
}

func parseOffsetArg(s string) (int, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseInt(s, base, 32)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

func cmdReport() *cobra.Command {
	var in, out string
	c := &cobra.Command{
		Use:   "report",
		Short: "Re-render a saved JSON analysis report as text or HTML",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := in
			if path == "" {
				root := projectRootForAnalyze()
				if root != "" {
					path = filepath.Join(root, "reports", "last.json")
				} else {
					path = "reports/last.json"
				}
			}
			var res wt.Result
			if err := report.ReadJSON(path, &res); err != nil {
				return fmt.Errorf("%w: load report %s: %v", wt.ErrNotFound, path, err)
			}
			fmtFormat, err := parseFormat()
			if err != nil {
				return err
			}
			var w = os.Stdout
			var closer func()
			if out != "" && out != "-" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				w = f
				closer = func() { f.Close() }
			}
			if closer != nil {
				defer closer()
			}
			if err := report.Write(w, &res, nil, fmtFormat, flagColor); err != nil {
				return err
			}
			if out != "" && out != "-" {
				fmt.Fprintf(os.Stderr, "wrote %s\n", out)
			}
			return nil
		},
	}
	c.Flags().StringVarP(&in, "in", "i", "", "input JSON report (default reports/last.json)")
	c.Flags().StringVarP(&out, "out", "o", "", "output path (default stdout)")
	return c
}

func cmdReplay() *cobra.Command {
	var reportPath string
	c := &cobra.Command{
		Use:   "replay [path]",
		Short: "Re-run analysis using budget/settings from a saved report",
		Long:  "Loads config_fingerprint metadata from a prior JSON report (budget) and re-analyzes the dataset for reproducibility demos.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := reportPath
			if path == "" {
				root := projectRootForAnalyze()
				if root != "" {
					path = filepath.Join(root, "reports", "last.json")
				} else {
					path = "reports/last.json"
				}
			}
			var prev wt.Result
			if err := report.ReadJSON(path, &prev); err != nil {
				return fmt.Errorf("%w: load report %s: %v", wt.ErrNotFound, path, err)
			}
			budget := wt.Budget(prev.Budget)
			if budget == "" {
				budget = wt.BudgetNormal
			}
			if _, err := wt.ParseBudget(string(budget)); err != nil {
				budget = wt.BudgetNormal
			}
			ds, err := loadDataset(args)
			if err != nil {
				return err
			}
			cfg := wt.DefaultPassConfig(budget)
			cfg.Jobs = flagJobs
			res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
				Budget: budget, Timeout: flagTimeout, ProjectRoot: projectRootForAnalyze(), Config: &cfg,
				Progress: progressReporter(),
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "replay: prior_config=%s new_config=%s prior_dataset=%s new_dataset=%s\n",
				prev.ConfigFingerprint, res.ConfigFingerprint, prev.DatasetFingerprint, res.DatasetFingerprint)
			fmtFormat, err := parseFormat()
			if err != nil {
				return err
			}
			return report.Write(os.Stdout, res, ds, fmtFormat, flagColor)
		},
	}
	c.Flags().StringVar(&reportPath, "from", "", "prior JSON report path")
	return c
}

func progressReporter() wt.ProgressFunc {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil
	}
	if os.Getenv("NO_PROGRESS") != "" {
		return nil
	}
	return func(done, total int, passName string) {
		fmt.Fprintf(os.Stderr, "wiretap: analyze %d/%d %s\n", done, total, passName)
	}
}

func saveLastReport(res *wt.Result) {
	if res == nil {
		return
	}
	root := projectRootForAnalyze()
	dir := "reports"
	if root != "" {
		dir = filepath.Join(root, "reports")
	}
	_ = os.MkdirAll(dir, 0o755)
	_ = report.WriteJSON(filepath.Join(dir, "last.json"), res)
}

func cmdCompareSchemas() *cobra.Command {
	return &cobra.Command{
		Use:   "compare-schemas <a> <b>",
		Short: "Alias for schema diff",
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
	}
}
