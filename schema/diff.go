package schema

import (
	"fmt"
	"sort"
	"strings"
)

// DiffChange describes one schema difference.
type DiffChange struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"` // added|removed|changed
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// DiffResult holds schema comparison.
type DiffResult struct {
	Changes []DiffChange `json:"changes"`
}

// Diff compares two schemas field-by-field (deterministic).
func Diff(a, b *Schema) DiffResult {
	am := flattenFields(a)
	bm := flattenFields(b)
	keys := map[string]struct{}{}
	for k := range am {
		keys[k] = struct{}{}
	}
	for k := range bm {
		keys[k] = struct{}{}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var changes []DiffChange
	for _, k := range sorted {
		fa, oka := am[k]
		fb, okb := bm[k]
		switch {
		case oka && !okb:
			changes = append(changes, DiffChange{Path: k, Kind: "removed", Before: fieldSummary(fa)})
		case !oka && okb:
			changes = append(changes, DiffChange{Path: k, Kind: "added", After: fieldSummary(fb)})
		default:
			sa, sb := fieldSummary(fa), fieldSummary(fb)
			if sa != sb {
				changes = append(changes, DiffChange{Path: k, Kind: "changed", Before: sa, After: sb})
			}
		}
	}
	return DiffResult{Changes: changes}
}

func flattenFields(s *Schema) map[string]Field {
	out := map[string]Field{}
	if s == nil {
		return out
	}
	var walk func([]Field, string)
	walk = func(fields []Field, prefix string) {
		for _, f := range fields {
			p := prefix + "/" + f.Name
			out[p] = f
			if len(f.Children) > 0 {
				walk(f.Children, p)
			}
		}
	}
	walk(s.Fields, "")
	return out
}

func fieldSummary(f Field) string {
	off := "-"
	if f.Offset != nil {
		off = fmt.Sprintf("%d", *f.Offset)
	}
	return fmt.Sprintf("type=%s off=%s len=%d endian=%s", f.Type, off, f.Length, f.Endian)
}

// FormatDiff returns a human-readable diff.
func FormatDiff(d DiffResult) string {
	if len(d.Changes) == 0 {
		return "schemas identical\n"
	}
	var b strings.Builder
	for _, c := range d.Changes {
		switch c.Kind {
		case "added":
			fmt.Fprintf(&b, "+ %s  %s\n", c.Path, c.After)
		case "removed":
			fmt.Fprintf(&b, "- %s  %s\n", c.Path, c.Before)
		case "changed":
			fmt.Fprintf(&b, "~ %s  %s → %s\n", c.Path, c.Before, c.After)
		}
	}
	return b.String()
}

// AnnOverlay is a minimal annotation overlay for MergeAnnotations (avoids project import).
type AnnOverlay struct {
	Offset int
	Length int
	Kind   string
	Label  string
	Note   string
}

// MergeAnnotations merges annotation overlays into a schema as trusted field overlays.
func MergeAnnotations(s *Schema, anns []AnnOverlay) *Schema {
	if s == nil {
		s = &Schema{Name: "merged", Version: "0.1.0"}
	}
	out := *s
	out.Fields = append([]Field{}, s.Fields...)
	for _, a := range anns {
		off := a.Offset
		updated := false
		for i := range out.Fields {
			f := &out.Fields[i]
			if f.Offset != nil && *f.Offset == off {
				if a.Label != "" {
					f.Name = a.Label
				}
				if a.Kind != "" {
					f.Type = mapAnnType(a.Kind)
				}
				if a.Note != "" {
					f.Description = a.Note
				}
				f.Confidence = "High"
				f.Evidence = "human annotation (trusted)"
				updated = true
				break
			}
		}
		if !updated {
			name := a.Label
			if name == "" {
				name = fmt.Sprintf("ann_%d", off)
			}
			length := a.Length
			if length <= 0 {
				length = 1
			}
			o := off
			out.Fields = append(out.Fields, Field{
				Name: name, Offset: &o, Length: length,
				Type: mapAnnType(a.Kind), Description: a.Note,
				Confidence: "High", Evidence: "human annotation (trusted)",
			})
		}
	}
	sort.SliceStable(out.Fields, func(i, j int) bool {
		oi, oj := 1<<30, 1<<30
		if out.Fields[i].Offset != nil {
			oi = *out.Fields[i].Offset
		}
		if out.Fields[j].Offset != nil {
			oj = *out.Fields[j].Offset
		}
		return oi < oj
	})
	return &out
}

func mapAnnType(kind string) string {
	switch strings.ToLower(kind) {
	case "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "string", "bytes", "checksum", "bitfield", "array", "struct":
		return strings.ToLower(kind)
	case "length":
		return "u16"
	case "field", "":
		return "bytes"
	default:
		return "bytes"
	}
}
