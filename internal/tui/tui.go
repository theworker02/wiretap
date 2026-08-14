package tui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/theworker02/wiretap/internal/cluster"
	"github.com/theworker02/wiretap/internal/inference"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// BrowseReport is an interactive section browser over an analysis report.
// Uses Bubble Tea + lipgloss when stdin/stdout are TTYs and NO_COLOR is unset;
// otherwise falls back to the stdlib line navigator (plain text).
func BrowseReport(out io.Writer, in io.Reader, res *wt.Result, ds *wt.Dataset) error {
	if res == nil {
		return wt.ErrNotFound
	}
	if useBubbleTea(out, in) {
		return runBubble(res, ds)
	}
	return browseStdlib(out, in, res, ds)
}

func useBubbleTea(out io.Writer, in io.Reader) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("WIRETAP_TUI"))); v == "plain" || v == "stdlib" {
		return false
	}
	of, okOut := out.(*os.File)
	inf, okIn := in.(*os.File)
	if !okOut || !okIn {
		return false
	}
	return isTerminal(of) && isTerminal(inf)
}

// browseStdlib is the portable NO_COLOR / non-TTY navigator.
func browseStdlib(out io.Writer, in io.Reader, res *wt.Result, ds *wt.Dataset) error {
	var cr *cluster.Result
	if ds != nil {
		cr, _ = cluster.ClusterMessages(ds, cluster.Options{MultiSignal: true})
	}

	printHelp := func() {
		fmt.Fprintln(out, "Wiretap TUI — sections:")
		fmt.Fprintln(out, "  1/s summary     2/w warnings    3/h hypotheses")
		fmt.Fprintln(out, "  4/o observations 5/e entropy    6/c clusters")
		fmt.Fprintln(out, "  x <off> explain-at-offset   j <off> jump   q quit")
	}
	printHelp()
	fmt.Fprint(out, formatSummary(res, ds))

	sc := newLineScanner(in)
	for {
		fmt.Fprint(out, "\n> ")
		line, ok := sc.Scan()
		if !ok {
			break
		}
		fields := strings.Fields(strings.TrimSpace(line))
		cmd := ""
		if len(fields) > 0 {
			cmd = fields[0]
		}
		switch cmd {
		case "q", "quit", "exit":
			return nil
		case "1", "s", "summary":
			fmt.Fprint(out, formatSummary(res, ds))
		case "2", "w", "warnings":
			if len(res.Warnings) == 0 {
				fmt.Fprintln(out, "(no warnings)")
			} else {
				for _, w := range res.Warnings {
					fmt.Fprintln(out, w)
				}
			}
		case "3", "h", "hypotheses":
			fmt.Fprint(out, formatHyps(res))
		case "4", "o", "observations":
			fmt.Fprint(out, formatObs(res))
		case "5", "e", "entropy":
			fmt.Fprint(out, formatEntropy(res))
		case "6", "c", "clusters":
			fmt.Fprint(out, formatClusters(cr))
		case "x", "explain":
			if len(fields) < 2 {
				fmt.Fprintln(out, "usage: x <offset>")
				continue
			}
			off, err := strconv.Atoi(strings.TrimPrefix(fields[1], "0x"))
			if err != nil {
				fmt.Fprintf(out, "bad offset: %v\n", err)
				continue
			}
			fmt.Fprint(out, formatExplain(res, ds, off))
		case "j", "jump":
			if len(fields) < 2 {
				fmt.Fprintln(out, "usage: j <offset>")
				continue
			}
			off, err := strconv.Atoi(strings.TrimPrefix(fields[1], "0x"))
			if err != nil {
				fmt.Fprintf(out, "bad offset: %v\n", err)
				continue
			}
			fmt.Fprintf(out, "offset %d — overlapping hypotheses:\n", off)
			for _, h := range inference.ExplainCompetition(res.Hypotheses, off, off+1, 5) {
				fmt.Fprintf(out, "  %s %s conf=%s\n", h.ID, h.Kind, h.Confidence.Level)
			}
			if ds != nil && ds.Len() > 0 && off < len(ds.Messages[0].Data) {
				fmt.Fprintf(out, "  msg0 byte=0x%02x\n", ds.Messages[0].Data[off])
			}
		case "help", "?":
			printHelp()
		case "":
			continue
		default:
			fmt.Fprintf(out, "unknown %q (help for commands)\n", cmd)
		}
	}
	return sc.Err()
}

func formatExplain(res *wt.Result, ds *wt.Dataset, off int) string {
	var b strings.Builder
	top := inference.ExplainCompetition(res.Hypotheses, off, off+1, 8)
	if len(top) == 0 {
		fmt.Fprintf(&b, "no hypotheses overlapping offset %d\n", off)
		return b.String()
	}
	fmt.Fprintf(&b, "Top hypotheses at offset %d:\n", off)
	for i, h := range top {
		fmt.Fprintf(&b, "  %d. %s %s conf=%s score=%.2f\n     %s\n",
			i+1, h.ID, h.Kind, h.Confidence.Level, h.Confidence.Score, h.Description)
		if len(h.Alternates) > 0 {
			fmt.Fprintf(&b, "     alternates: %s\n", strings.Join(h.Alternates, ", "))
		}
		if reason, ok := h.Params["lost_to_reason"].(string); ok {
			fmt.Fprintf(&b, "     lost because: %s\n", reason)
		}
		for _, ev := range h.Confidence.Evidence {
			fmt.Fprintf(&b, "       [%s] %s\n", ev.Kind, ev.Description)
		}
	}
	if ds != nil && ds.Len() > 0 && off >= 0 && off < len(ds.Messages[0].Data) {
		fmt.Fprintf(&b, "  msg0 byte=0x%02x\n", ds.Messages[0].Data[off])
	}
	return b.String()
}

func formatSummary(res *wt.Result, ds *wt.Dataset) string {
	var b strings.Builder
	fmt.Fprintf(&b, "dataset=%s messages=%d lengths=%d..%d budget=%s elapsed_ms=%d elapsed_us=%d\n",
		res.DatasetName, res.MessageCount, res.MinLength, res.MaxLength, res.Budget, res.ElapsedMS, res.ElapsedUS)
	fmt.Fprintf(&b, "fingerprint=%s hypotheses=%d\n", res.DatasetFingerprint, len(res.Hypotheses))
	if ds != nil {
		fmt.Fprintf(&b, "loaded_name=%s\n", ds.Name)
	}
	return b.String()
}

func formatHyps(res *wt.Result) string {
	var b strings.Builder
	limit := 40
	for i, h := range res.Hypotheses {
		if i >= limit {
			fmt.Fprintf(&b, "… %d more\n", len(res.Hypotheses)-limit)
			break
		}
		fmt.Fprintf(&b, "%s  %s off=%d len=%d conf=%s score=%.2f\n  %s\n",
			h.ID, h.Kind, h.Offset, h.Length, h.Confidence.Level, h.Confidence.Score, h.Description)
	}
	if len(res.Hypotheses) == 0 {
		b.WriteString("(none)\n")
	}
	return b.String()
}

func formatObs(res *wt.Result) string {
	var b strings.Builder
	limit := 40
	for i, o := range res.Observations {
		if i >= limit {
			fmt.Fprintf(&b, "… %d more\n", len(res.Observations)-limit)
			break
		}
		fmt.Fprintf(&b, "%s  %s\n", o.Kind, o.Description)
	}
	return b.String()
}

func formatEntropy(res *wt.Result) string {
	var b strings.Builder
	if len(res.Regions) == 0 && len(res.Stats) == 0 {
		return "(no entropy data in report — run analyze with stats retained)\n"
	}
	for _, r := range res.Regions {
		fmt.Fprintf(&b, "region [%d:%d] %s entropy_mean=%.2f\n", r.Start, r.End, r.Kind, r.EntropyMean)
	}
	limit := 24
	for i, s := range res.Stats {
		if i >= limit {
			fmt.Fprintf(&b, "… %d more offsets\n", len(res.Stats)-limit)
			break
		}
		bar := strings.Repeat("#", int(s.Entropy+0.5))
		fmt.Fprintf(&b, "%4d  H=%.2f  u=%d  %s\n", s.Offset, s.Entropy, s.Unique, bar)
	}
	return b.String()
}

func formatClusters(cr *cluster.Result) string {
	if cr == nil || len(cr.Clusters) == 0 {
		return "(no clusters)\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "clusters=%d hierarchy=%d\n", len(cr.Clusters), len(cr.Hierarchy))
	for _, c := range cr.Clusters {
		fmt.Fprintf(&b, "  %s size=%d len=%d prefix=%x H̄=%.2f\n", c.ID, c.Size, c.Length, c.ConstantPref, c.EntropyMean)
	}
	for _, t := range cr.TypeFields {
		fmt.Fprintf(&b, "typefield off=%d w=%d conf=%s — %s\n", t.Offset, t.Length, t.Confidence.Level, t.Description)
	}
	return b.String()
}

func formatWarnings(res *wt.Result) string {
	if len(res.Warnings) == 0 {
		return "(no warnings)\n"
	}
	var b strings.Builder
	for _, w := range res.Warnings {
		b.WriteString(w)
		b.WriteByte('\n')
	}
	return b.String()
}
