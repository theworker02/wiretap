package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// Format is the output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	// FormatHTML is defined in html.go
)

// Write writes a result in the requested format.
func Write(w io.Writer, res *wt.Result, ds *wt.Dataset, format Format, color bool) error {
	if res == nil {
		return fmt.Errorf("nil result")
	}
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case FormatHTML:
		return WriteHTML(w, res, ds)
	default:
		return writeText(w, res, ds, color)
	}
}

func useColor(color bool) bool {
	if !color {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return true
}

func writeText(w io.Writer, res *wt.Result, ds *wt.Dataset, color bool) error {
	color = useColor(color)
	bold := func(s string) string {
		if !color {
			return s
		}
		return "\x1b[1m" + s + "\x1b[0m"
	}
	dim := func(s string) string {
		if !color {
			return s
		}
		return "\x1b[2m" + s + "\x1b[0m"
	}
	cyan := func(s string) string {
		if !color {
			return s
		}
		return "\x1b[36m" + s + "\x1b[0m"
	}

	fmt.Fprintf(w, "%s\n", bold("Wiretap Analysis Report"))
	fmt.Fprintf(w, "schema=%s  budget=%s  messages=%d  lengths=%d..%d\n",
		res.SchemaVersion, res.Budget, res.MessageCount, res.MinLength, res.MaxLength)
	fmt.Fprintf(w, "dataset_fingerprint=%s\n", res.DatasetFingerprint)
	fmt.Fprintf(w, "config_fingerprint=%s\n", res.ConfigFingerprint)
	if res.ToolVersion != "" {
		fmt.Fprintf(w, "tool=%s", res.ToolVersion)
		if res.ToolCommit != "" {
			fmt.Fprintf(w, " commit=%s", res.ToolCommit)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "elapsed_ms=%d elapsed_us=%d\n\n", res.ElapsedMS, res.ElapsedUS)

	if len(res.Warnings) > 0 {
		fmt.Fprintf(w, "%s\n", bold("Warnings"))
		for _, wmsg := range res.Warnings {
			fmt.Fprintf(w, "  - %s\n", wmsg)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s\n", bold("Observations (measured)"))
	if len(res.Constants) == 0 && len(res.Regions) == 0 {
		fmt.Fprintf(w, "  (none beyond byte stats)\n")
	}
	for _, c := range res.Constants {
		val := byte(0)
		if c.Value != nil {
			val = *c.Value
		}
		fmt.Fprintf(w, "  constant [%d:%d] = 0x%02x  confidence=%s\n", c.Start, c.End, val, c.Confidence.Level)
	}
	for _, r := range res.Regions {
		if r.Kind == "constant" {
			continue
		}
		fmt.Fprintf(w, "  region [%d:%d] kind=%s entropy_mean=%.2f\n", r.Start, r.End, r.Kind, r.EntropyMean)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", bold("Hypotheses (competing; evidence-backed)"))
	if len(res.Hypotheses) == 0 {
		fmt.Fprintf(w, "  Insufficient evidence for field hypotheses.\n")
	}
	shown := 0
	for _, h := range res.Hypotheses {
		if shown >= 40 {
			fmt.Fprintf(w, "  … %d more hypotheses omitted (use --format json)\n", len(res.Hypotheses)-shown)
			break
		}
		fmt.Fprintf(w, "  %s  %s  off=%d len=%d  %s=%s score=%.2f\n",
			cyan(h.ID), h.Kind, h.Offset, h.Length, bold("confidence"), h.Confidence.Level, h.Confidence.Score)
		fmt.Fprintf(w, "    %s\n", h.Description)
		for _, e := range h.Confidence.Evidence {
			fmt.Fprintf(w, "    %s %s", dim("·"), e.Kind)
			if e.Metric != "" {
				fmt.Fprintf(w, " %s=%.4g", e.Metric, e.Value)
			}
			fmt.Fprintf(w, " — %s\n", e.Description)
		}
		shown++
	}
	fmt.Fprintln(w)

	if ds != nil && ds.Len() > 0 {
		fmt.Fprintf(w, "%s\n", bold("Annotated hex"))
		m := ds.Messages[0]
		fmt.Fprintf(w, "representative id=%s len=%d", m.ID, len(m.Data))
		if ds.Len() > 1 {
			fmt.Fprintf(w, " (of %d messages)", ds.Len())
		}
		fmt.Fprintln(w)
		WriteAnnotatedHex(w, m.Data, res, color)
	}
	return nil
}

// fieldMark assigns a stable letter to a hypothesis for the legend.
type fieldMark struct {
	Letter string
	Hyp    wt.Hypothesis
}

func buildMarks(data []byte, res *wt.Result) (map[int]string, []fieldMark) {
	marks := map[int]string{}
	var legend []fieldMark
	if res == nil {
		return marks, legend
	}
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	li := 0
	for _, c := range res.Constants {
		letter := "C"
		if li < len(letters) {
			letter = string(letters[li])
			li++
		}
		legend = append(legend, fieldMark{Letter: letter, Hyp: wt.Hypothesis{
			ID: "constant", Kind: "constant", Offset: c.Start, Length: c.End - c.Start,
			Description: "constant region", Confidence: c.Confidence,
		}})
		for i := c.Start; i < c.End && i < len(data); i++ {
			if marks[i] == "" {
				marks[i] = letter
			}
		}
	}
	for _, h := range res.Hypotheses {
		if h.Confidence.Level != wt.ConfidenceHigh && h.Confidence.Level != wt.ConfidenceMedium {
			continue
		}
		if h.Offset < 0 || h.Length <= 0 {
			continue
		}
		letter := "?"
		if li < len(letters) {
			letter = string(letters[li])
			li++
		}
		legend = append(legend, fieldMark{Letter: letter, Hyp: h})
		for i := h.Offset; i < h.Offset+h.Length && i < len(data); i++ {
			if marks[i] == "" {
				marks[i] = letter
			}
		}
		if li >= 26 {
			break
		}
	}
	return marks, legend
}

// WriteAnnotatedHex prints hex with multi-field letter marks and legend (NO_COLOR-safe).
func WriteAnnotatedHex(w io.Writer, data []byte, res *wt.Result, color bool) {
	color = useColor(color)
	marks, legend := buildMarks(data, res)
	const row = 16
	for off := 0; off < len(data); off += row {
		end := off + row
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(w, "%04x  ", off)
		ascii := make([]byte, 0, row)
		for i := off; i < end; i++ {
			b := data[i]
			cell := fmt.Sprintf("%02x", b)
			if m := marks[i]; m != "" && color {
				cell = "\x1b[33m" + cell + "\x1b[0m"
			}
			fmt.Fprintf(w, "%s ", cell)
			if b >= 32 && b < 127 {
				ascii = append(ascii, b)
			} else {
				ascii = append(ascii, '.')
			}
		}
		for i := end - off; i < row; i++ {
			fmt.Fprint(w, "   ")
		}
		fmt.Fprintf(w, " |%s|\n", string(ascii))
		// underline / letter row
		fmt.Fprint(w, "      ")
		for i := off; i < end; i++ {
			m := marks[i]
			if m == "" {
				fmt.Fprint(w, "   ")
			} else {
				fmt.Fprintf(w, " %s ", m)
			}
		}
		fmt.Fprintln(w)
	}
	if len(legend) > 0 {
		fmt.Fprintln(w, "legend:")
		for _, lm := range legend {
			fmt.Fprintf(w, "  %s  %-12s off=%d len=%d  %s  conf=%s\n",
				lm.Letter, lm.Hyp.Kind, lm.Hyp.Offset, lm.Hyp.Length, lm.Hyp.ID, lm.Hyp.Confidence.Level)
		}
	}
}

// Selector describes an explain target.
type Selector struct {
	Kind   string // id | field | offset | range
	ID     string
	Start  int
	End    int // exclusive for range; for field/offset End=Start+1 or length
	Length int
}

// ParseSelector parses field:N, 0xNN, offset:N, 0x02..0x03, or bare id substring.
func ParseSelector(s string) (Selector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Selector{}, fmt.Errorf("%w: empty selector", wt.ErrInvalidConfig)
	}
	if strings.Contains(s, "..") {
		parts := strings.SplitN(s, "..", 2)
		a, err1 := parseOffsetToken(parts[0])
		b, err2 := parseOffsetToken(parts[1])
		if err1 != nil || err2 != nil {
			return Selector{}, fmt.Errorf("%w: bad range %q", wt.ErrInvalidConfig, s)
		}
		if b < a {
			a, b = b, a
		}
		return Selector{Kind: "range", Start: a, End: b + 1, Length: b - a + 1}, nil
	}
	if strings.HasPrefix(strings.ToLower(s), "field:") {
		n, err := parseOffsetToken(s[len("field:"):])
		if err != nil {
			return Selector{}, err
		}
		return Selector{Kind: "field", Start: n, End: n + 1, Length: 1}, nil
	}
	if strings.HasPrefix(strings.ToLower(s), "offset:") {
		n, err := parseOffsetToken(s[len("offset:"):])
		if err != nil {
			return Selector{}, err
		}
		return Selector{Kind: "offset", Start: n, End: n + 1, Length: 1}, nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := parseOffsetToken(s)
		if err != nil {
			return Selector{}, err
		}
		return Selector{Kind: "offset", Start: n, End: n + 1, Length: 1}, nil
	}
	// bare decimal offset?
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return Selector{Kind: "offset", Start: n, End: n + 1, Length: 1}, nil
	}
	return Selector{Kind: "id", ID: s}, nil
}

func parseOffsetToken(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("%w: bad hex offset %q", wt.ErrInvalidConfig, s)
		}
		return int(v), nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%w: bad offset %q", wt.ErrInvalidConfig, s)
	}
	return v, nil
}

// Explain prints hypothesis detail for an id or competing hypotheses at an offset/range.
func Explain(w io.Writer, res *wt.Result, sel Selector) error {
	if res == nil {
		return wt.ErrNotFound
	}
	if sel.Kind == "id" {
		return ExplainHypothesis(w, res, sel.ID)
	}
	type ranked struct {
		h wt.Hypothesis
	}
	var hits []ranked
	for _, h := range res.Hypotheses {
		if hypOverlaps(h, sel.Start, sel.End) {
			hits = append(hits, ranked{h})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i].h.Confidence.Score > hits[j].h.Confidence.Score
	})
	fmt.Fprintf(w, "Explain selector %s [%d:%d] — %d competing hypotheses\n\n", sel.Kind, sel.Start, sel.End, len(hits))
	if len(hits) == 0 {
		fmt.Fprintln(w, "Insufficient evidence: no hypotheses overlap this range.")
		return nil
	}
	for i, hit := range hits {
		h := hit.h
		fmt.Fprintf(w, "#%d  %s  kind=%s off=%d len=%d  confidence=%s score=%.3f\n",
			i+1, h.ID, h.Kind, h.Offset, h.Length, h.Confidence.Level, h.Confidence.Score)
		fmt.Fprintf(w, "    %s\n", h.Description)
		var support, against []wt.EvidenceItem
		for _, e := range h.Confidence.Evidence {
			if e.Kind == "contradict" {
				against = append(against, e)
			} else {
				support = append(support, e)
			}
		}
		for i, e := range support {
			if i >= 3 {
				break
			}
			fmt.Fprintf(w, "    + %s", e.Description)
			if e.Metric != "" {
				fmt.Fprintf(w, " (%s=%.4g)", e.Metric, e.Value)
			}
			fmt.Fprintln(w)
		}
		for _, e := range against {
			fmt.Fprintf(w, "    - %s\n", e.Description)
		}
		fmt.Fprintln(w)
	}
	return nil
}

func hypOverlaps(h wt.Hypothesis, start, end int) bool {
	if h.Offset < 0 {
		return false
	}
	hl := h.Length
	if hl <= 0 {
		hl = 1
	}
	return h.Offset < end && start < h.Offset+hl
}

// ExplainHypothesis prints detailed evidence for one hypothesis ID.
func ExplainHypothesis(w io.Writer, res *wt.Result, id string) error {
	if res == nil {
		return wt.ErrNotFound
	}
	for _, h := range res.Hypotheses {
		if h.ID == id || strings.Contains(h.ID, id) {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(h)
		}
	}
	return fmt.Errorf("%w: hypothesis %q", wt.ErrNotFound, id)
}
