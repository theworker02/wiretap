package visualize

import (
	"fmt"
	"html"
	"os"
	"strings"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

// Options for SVG field map rendering.
type Options struct {
	Width      int
	BytesShown int // max bytes on the lane (0 = auto from max length / schema)
	Title      string
}

// RenderSVG builds a pure-SVG annotated byte lane from a report and/or schema.
func RenderSVG(res *wt.Result, sch *schema.Schema, opts Options) ([]byte, error) {
	if opts.Width <= 0 {
		opts.Width = 960
	}
	maxLen := 0
	if res != nil {
		maxLen = res.MaxLength
	}
	if sch != nil {
		for _, f := range sch.Fields {
			if f.Offset != nil && *f.Offset+f.Length > maxLen {
				maxLen = *f.Offset + f.Length
			}
		}
	}
	if opts.BytesShown > 0 && opts.BytesShown < maxLen {
		maxLen = opts.BytesShown
	}
	if maxLen <= 0 {
		maxLen = 32
	}
	if opts.Title == "" {
		opts.Title = "Wiretap field map"
	}

	type seg struct {
		start, end int
		label      string
		level      string
		kind       string
	}
	var segs []seg
	if sch != nil {
		var walk func([]schema.Field)
		walk = func(fields []schema.Field) {
			for _, f := range fields {
				if f.Offset != nil && f.Length > 0 {
					segs = append(segs, seg{*f.Offset, *f.Offset + f.Length, f.Name, f.Confidence, f.Type})
				}
				if len(f.Children) > 0 {
					walk(f.Children)
				}
			}
		}
		walk(sch.Fields)
	}
	if res != nil {
		for _, h := range res.Hypotheses {
			if h.Offset < 0 || h.Length <= 0 {
				continue
			}
			if h.Confidence.Level != wt.ConfidenceHigh && h.Confidence.Level != wt.ConfidenceMedium {
				continue
			}
			segs = append(segs, seg{h.Offset, h.Offset + h.Length, h.Kind, string(h.Confidence.Level), h.Kind})
		}
	}

	laneY := 80
	byteW := float64(opts.Width-80) / float64(maxLen)
	if byteW < 4 {
		byteW = 4
		opts.Width = int(byteW*float64(maxLen)) + 80
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`+"\n",
		opts.Width, 220+len(segs)*2, opts.Width, 220)
	b.WriteString(`<style>
  .title { font: 600 16px ui-monospace, Consolas, monospace; fill: #1a3a4a; }
  .label { font: 11px ui-monospace, Consolas, monospace; fill: #1a3a4a; }
  .muted { font: 10px ui-monospace, Consolas, monospace; fill: #5a6a72; }
  .lane { fill: #e8eef1; stroke: #1a3a4a; stroke-width: 1; }
</style>` + "\n")
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#f7f5f0"/>`+"\n")
	fmt.Fprintf(&b, `<text x="24" y="28" class="title">%s</text>`+"\n", html.EscapeString(opts.Title))
	fmt.Fprintf(&b, `<text x="24" y="48" class="muted">bytes 0..%d — confidence colors are measured levels, not invented scores</text>`+"\n", maxLen-1)

	fmt.Fprintf(&b, `<rect class="lane" x="40" y="%d" width="%.1f" height="28" rx="2"/>`+"\n", laneY, float64(maxLen)*byteW)

	for i := 0; i <= maxLen; i += max(1, maxLen/16) {
		x := 40 + float64(i)*byteW
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="#9aa8b0" stroke-width="1"/>`+"\n", x, laneY, x, laneY+28)
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" class="muted" text-anchor="middle">%d</text>`+"\n", x, laneY+42, i)
	}

	for _, s := range segs {
		if s.start >= maxLen {
			continue
		}
		end := s.end
		if end > maxLen {
			end = maxLen
		}
		x := 40 + float64(s.start)*byteW
		w := float64(end-s.start) * byteW
		if w < 2 {
			w = 2
		}
		color := colorFor(s.level)
		fmt.Fprintf(&b, `<rect x="%.1f" y="%d" width="%.1f" height="28" fill="%s" fill-opacity="0.75" stroke="#1a3a4a" stroke-width="0.5"><title>%s</title></rect>`+"\n",
			x, laneY, w, color, html.EscapeString(fmt.Sprintf("%s [%d:%d] %s", s.label, s.start, s.end, s.level)))
	}

	// Legend
	ly := laneY + 70
	fmt.Fprintf(&b, `<text x="40" y="%d" class="label">Legend</text>`+"\n", ly)
	for i, item := range []struct{ lvl, col string }{
		{"High", "#2f6f7e"}, {"Medium", "#c4a35a"}, {"Low", "#8a9a7b"}, {"Unknown/other", "#b0b8bc"},
	} {
		x := 40 + i*160
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="14" height="14" fill="%s"/>`+"\n", x, ly+10, item.col)
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="muted">%s</text>`+"\n", x+20, ly+21, item.lvl)
	}
	b.WriteString("</svg>\n")
	return []byte(b.String()), nil
}

func colorFor(level string) string {
	switch strings.ToLower(level) {
	case "high":
		return "#2f6f7e"
	case "medium":
		return "#c4a35a"
	case "low":
		return "#8a9a7b"
	default:
		return "#b0b8bc"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// RenderHTML wraps SVG in a minimal HTML document (no JS required).
func RenderHTML(res *wt.Result, sch *schema.Schema, opts Options) ([]byte, error) {
	svg, err := RenderSVG(res, sch, opts)
	if err != nil {
		return nil, err
	}
	title := opts.Title
	if title == "" {
		title = "Wiretap field map"
	}
	doc := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>%s</title>
<style>body{margin:0;background:#f7f5f0;font-family:ui-monospace,Consolas,monospace}</style>
</head><body>%s</body></html>
`, html.EscapeString(title), string(svg))
	return []byte(doc), nil
}

// WriteFile writes SVG or HTML based on extension.
func WriteFile(path string, res *wt.Result, sch *schema.Schema, opts Options) error {
	var (
		data []byte
		err  error
	)
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") {
		data, err = RenderHTML(res, sch, opts)
	} else {
		data, err = RenderSVG(res, sch, opts)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
