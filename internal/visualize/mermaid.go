package visualize

import (
	"fmt"
	"os"
	"strings"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

// RenderMermaid builds a Mermaid flowchart from a schema (preferred) or High/Medium hypotheses.
func RenderMermaid(res *wt.Result, sch *schema.Schema) (string, error) {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("  classDef high fill:#2f6f7e,color:#fff,stroke:#1a3a4a\n")
	b.WriteString("  classDef med fill:#c4a35a,color:#1a3a4a,stroke:#1a3a4a\n")
	b.WriteString("  classDef low fill:#d5dde1,color:#1a3a4a,stroke:#9aa8b0\n")

	type node struct {
		id, label, class string
		off, length      int
	}
	var nodes []node
	if sch != nil && len(sch.Fields) > 0 {
		var walk func([]schema.Field, string)
		walk = func(fields []schema.Field, prefix string) {
			for i, f := range fields {
				id := fmt.Sprintf("n%s%d", prefix, i)
				off := "?"
				if f.Offset != nil {
					off = fmt.Sprintf("%d", *f.Offset)
				}
				label := fmt.Sprintf("%s[%s] (%s+%d)", sanitizeMermaid(f.Name), sanitizeMermaid(f.Type), off, f.Length)
				cls := "med"
				switch strings.ToLower(f.Confidence) {
				case "high":
					cls = "high"
				case "low", "insufficient", "unknown":
					cls = "low"
				}
				o := 0
				if f.Offset != nil {
					o = *f.Offset
				}
				nodes = append(nodes, node{id, label, cls, o, f.Length})
				if len(f.Children) > 0 {
					walk(f.Children, prefix+fmt.Sprintf("%d_", i))
				}
			}
		}
		walk(sch.Fields, "")
	} else if res != nil {
		for i, h := range res.Hypotheses {
			if h.Offset < 0 && h.Kind != "checksum" {
				continue
			}
			if h.Confidence.Level != wt.ConfidenceHigh && h.Confidence.Level != wt.ConfidenceMedium {
				continue
			}
			id := fmt.Sprintf("h%d", i)
			off := "trailer"
			if h.Offset >= 0 {
				off = fmt.Sprintf("%d", h.Offset)
			}
			label := fmt.Sprintf("%s (%s+%d)", sanitizeMermaid(h.Kind), off, h.Length)
			cls := "med"
			if h.Confidence.Level == wt.ConfidenceHigh {
				cls = "high"
			}
			nodes = append(nodes, node{id, label, cls, h.Offset, h.Length})
		}
	}
	if len(nodes) == 0 {
		b.WriteString("  empty[Insufficient evidence]\n")
		return b.String(), nil
	}
	// Sort by offset for left-to-right structure.
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if nodes[j].off >= 0 && (nodes[i].off < 0 || nodes[j].off < nodes[i].off) {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			}
		}
	}
	for _, n := range nodes {
		fmt.Fprintf(&b, "  %s[\"%s\"]:::%s\n", n.id, n.label, n.class)
	}
	for i := 0; i+1 < len(nodes); i++ {
		fmt.Fprintf(&b, "  %s --> %s\n", nodes[i].id, nodes[i+1].id)
	}
	return b.String(), nil
}

func sanitizeMermaid(s string) string {
	s = strings.ReplaceAll(s, `"`, "'")
	s = strings.ReplaceAll(s, "[", "(")
	s = strings.ReplaceAll(s, "]", ")")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// WriteMermaid writes a .mmd file.
func WriteMermaid(path string, res *wt.Result, sch *schema.Schema) error {
	s, err := RenderMermaid(res, sch)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(s), 0o644)
}

// RenderGraphvizDOT builds a simple Graphviz digraph (optional companion to Mermaid).
func RenderGraphvizDOT(res *wt.Result, sch *schema.Schema) (string, error) {
	mmd, err := RenderMermaid(res, sch)
	if err != nil {
		return "", err
	}
	// Convert mermaid-ish nodes into DOT by regenerating simply.
	_ = mmd
	var b strings.Builder
	b.WriteString("digraph wiretap {\n  rankdir=LR;\n  node [shape=box,fontname=\"Courier\"];\n")
	type item struct {
		id, label string
		off       int
	}
	var items []item
	if sch != nil {
		for i, f := range sch.Fields {
			off := 0
			offs := "?"
			if f.Offset != nil {
				off = *f.Offset
				offs = fmt.Sprintf("%d", off)
			}
			items = append(items, item{fmt.Sprintf("n%d", i), fmt.Sprintf("%s\\n%s+%d", f.Name, offs, f.Length), off})
		}
	} else if res != nil {
		for i, h := range res.Hypotheses {
			if h.Offset < 0 && h.Kind != "checksum" {
				continue
			}
			if h.Confidence.Level != wt.ConfidenceHigh && h.Confidence.Level != wt.ConfidenceMedium {
				continue
			}
			items = append(items, item{fmt.Sprintf("h%d", i), fmt.Sprintf("%s\\n%d+%d", h.Kind, h.Offset, h.Length), h.Offset})
		}
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].off >= 0 && (items[i].off < 0 || items[j].off < items[i].off) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	for _, it := range items {
		fmt.Fprintf(&b, "  %s [label=\"%s\"];\n", it.id, it.label)
	}
	for i := 0; i+1 < len(items); i++ {
		fmt.Fprintf(&b, "  %s -> %s;\n", items[i].id, items[i+1].id)
	}
	b.WriteString("}\n")
	return b.String(), nil
}
