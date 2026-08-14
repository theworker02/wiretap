package report

import (
	"fmt"
	"html"
	"io"
	"strings"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// FormatHTML is the self-contained HTML analysis report format.
const FormatHTML Format = "html"

// WriteHTML renders a printable, self-contained HTML report with hex dump,
// hypotheses, inline SVG entropy chart, and cluster metadata.
func WriteHTML(w io.Writer, res *wt.Result, ds *wt.Dataset) error {
	if res == nil {
		return fmt.Errorf("nil result")
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Wiretap Analysis Report</title>
<style>
:root{--ink:#1a3a4a;--muted:#5a6a72;--bg:#f7f5f0;--card:#fff;--accent:#2f6f7e;--med:#c4a35a;--line:#d5dde1}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 ui-monospace,Consolas,monospace}
header{padding:28px 32px 12px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#eef4f6,#f7f5f0)}
h1{margin:0 0 6px;font-size:22px}
h2{margin:28px 0 10px;font-size:15px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted)}
.meta,.muted{color:var(--muted);font-size:12px}
main{padding:8px 32px 48px;max-width:1100px}
.grid{display:grid;gap:8px}
.hyp{padding:10px 12px;background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent)}
.hyp.med{border-left-color:var(--med)}
.hyp.low{border-left-color:#8a9a7b}
.badge{display:inline-block;padding:1px 6px;border:1px solid var(--line);border-radius:3px;font-size:11px}
.hex{white-space:pre;overflow:auto;background:#1a3a4a;color:#d7e6ea;padding:14px;border-radius:4px;font-size:12px}
.warn{color:#8a4b2a}
@media print{header{background:#fff} .hyp{break-inside:avoid}}
</style></head><body>
`)
	fmt.Fprintf(&b, `<header><h1>Wiretap Analysis Report</h1>
<p class="meta">schema=%s · budget=%s · messages=%d · lengths=%d..%d</p>
<p class="meta">dataset_fingerprint=%s</p>
<p class="meta">config_fingerprint=%s</p>`,
		html.EscapeString(res.SchemaVersion), html.EscapeString(res.Budget),
		res.MessageCount, res.MinLength, res.MaxLength,
		html.EscapeString(res.DatasetFingerprint),
		html.EscapeString(res.ConfigFingerprint))
	if res.ToolVersion != "" {
		fmt.Fprintf(&b, `<p class="meta">tool=%s`, html.EscapeString(res.ToolVersion))
		if res.ToolCommit != "" {
			fmt.Fprintf(&b, ` commit=%s`, html.EscapeString(res.ToolCommit))
		}
		b.WriteString(`</p>`)
	}
	fmt.Fprintf(&b, `<p class="meta">elapsed_ms=%d elapsed_us=%d</p></header><main>`, res.ElapsedMS, res.ElapsedUS)

	if len(res.Warnings) > 0 {
		b.WriteString(`<h2>Warnings</h2><ul>`)
		for _, wmsg := range res.Warnings {
			fmt.Fprintf(&b, `<li class="warn">%s</li>`, html.EscapeString(wmsg))
		}
		b.WriteString(`</ul>`)
	}

	b.WriteString(`<h2>Entropy</h2>`)
	b.WriteString(entropySVG(res))

	if ds != nil && ds.Len() > 0 {
		b.WriteString(`<h2>Hex (first message)</h2><div class="hex">`)
		b.WriteString(html.EscapeString(hexDump(ds.Messages[0].Data, 16)))
		b.WriteString(`</div>`)
	}

	b.WriteString(`<h2>Hypotheses</h2><div class="grid">`)
	if len(res.Hypotheses) == 0 {
		b.WriteString(`<p class="muted">Insufficient evidence — no hypotheses retained.</p>`)
	}
	for _, h := range res.Hypotheses {
		cls := "hyp"
		switch h.Confidence.Level {
		case wt.ConfidenceMedium:
			cls = "hyp med"
		case wt.ConfidenceLow, wt.ConfidenceInsufficient, wt.ConfidenceUnknown:
			cls = "hyp low"
		}
		off := "n/a"
		if h.Offset >= 0 {
			off = fmt.Sprintf("%d..%d", h.Offset, h.Offset+h.Length)
		} else if h.Kind == "checksum" {
			off = "trailer"
		}
		fmt.Fprintf(&b, `<div class="%s"><div><span class="badge">%s</span> <span class="badge">%s</span> <strong>%s</strong></div>
<p class="muted">offset=%s · score=%.2f · id=%s</p>
<p>%s</p></div>`,
			cls,
			html.EscapeString(h.Kind),
			html.EscapeString(string(h.Confidence.Level)),
			html.EscapeString(h.ID),
			html.EscapeString(off),
			h.Confidence.Score,
			html.EscapeString(h.ID),
			html.EscapeString(h.Description))
	}
	b.WriteString(`</div>`)

	if len(res.Regions) > 0 {
		b.WriteString(`<h2>Regions</h2><ul>`)
		for _, r := range res.Regions {
			fmt.Fprintf(&b, `<li>[%d:%d] %s entropy_mean=%.2f</li>`, r.Start, r.End, html.EscapeString(r.Kind), r.EntropyMean)
		}
		b.WriteString(`</ul>`)
	}

	if c := res.Meta["clusters"]; c != "" {
		fmt.Fprintf(&b, `<h2>Clusters</h2><p class="muted">clusters=%s`, html.EscapeString(c))
		if h := res.Meta["cluster_hierarchy"]; h != "" {
			fmt.Fprintf(&b, ` · hierarchy=%s`, html.EscapeString(h))
		}
		b.WriteString(`</p>`)
	}

	b.WriteString(`<p class="muted" style="margin-top:36px">Confidence levels are evidence-derived. Insufficient evidence is preferred over hype. Offline · deterministic · no LLM APIs.</p>`)
	b.WriteString(`</main></body></html>`)
	_, err := io.WriteString(w, b.String())
	return err
}

func entropySVG(res *wt.Result) string {
	stats := res.Stats
	if len(stats) == 0 {
		return `<p class="muted">No per-offset stats in report (JSON may omit bulk stats).</p>`
	}
	width := 900
	height := 120
	n := len(stats)
	if n > 256 {
		n = 256
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="entropy chart">`, width, height, width, height)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff" stroke="#d5dde1"/>`)
	bw := float64(width-40) / float64(n)
	for i := 0; i < n; i++ {
		e := stats[i].Entropy
		if e < 0 {
			e = 0
		}
		if e > 8 {
			e = 8
		}
		h := e / 8 * float64(height-30)
		x := 20 + float64(i)*bw
		y := float64(height-20) - h
		col := "#2f6f7e"
		if e >= 6.5 {
			col = "#c4a35a"
		} else if e < 2 {
			col = "#8a9a7b"
		}
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"/>`, x, y, bw*0.9, h, col)
	}
	b.WriteString(`<text x="20" y="14" fill="#5a6a72" font-size="11">entropy 0..8 by offset</text></svg>`)
	return b.String()
}

func hexDump(data []byte, width int) string {
	if width <= 0 {
		width = 16
	}
	var b strings.Builder
	for i := 0; i < len(data); i += width {
		fmt.Fprintf(&b, "%04x  ", i)
		end := i + width
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < end; j++ {
			fmt.Fprintf(&b, "%02x ", data[j])
		}
		for j := end; j < i+width; j++ {
			b.WriteString("   ")
		}
		b.WriteString(" |")
		for j := i; j < end; j++ {
			c := data[j]
			if c < 32 || c > 126 {
				c = '.'
			}
			b.WriteByte(c)
		}
		b.WriteString("|\n")
	}
	return b.String()
}
