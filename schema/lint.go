package schema

import (
	"fmt"
	"strings"
)

// LintIssue is a non-fatal schema quality finding.
type LintIssue struct {
	Severity string // warning | info
	Path     string
	Message  string
}

func (i LintIssue) String() string {
	return fmt.Sprintf("%s: %s: %s", i.Severity, i.Path, i.Message)
}

// Lint returns quality warnings beyond structural Validate errors.
// It does not invent protocol facts — only flags schema hygiene problems.
func Lint(s *Schema) []LintIssue {
	if s == nil {
		return []LintIssue{{Severity: "warning", Path: "/", Message: "nil schema"}}
	}
	var out []LintIssue
	if s.Version == "" {
		out = append(out, LintIssue{Severity: "info", Path: s.Name, Message: "schema version unset"})
	}
	if s.Endian == "" || s.Endian == "mixed" {
		out = append(out, LintIssue{Severity: "info", Path: s.Name, Message: "top-level endian is unset or mixed — multi-byte fields should set endian explicitly"})
	}
	type span struct {
		name string
		s, e int
	}
	var spans []span
	var walk func(prefix string, fields []Field)
	walk = func(prefix string, fields []Field) {
		for i, f := range fields {
			path := prefix + f.Name
			if f.Name == "" {
				path = fmt.Sprintf("%sfield[%d]", prefix, i)
				out = append(out, LintIssue{Severity: "warning", Path: path, Message: "unnamed field"})
			}
			if f.Type == "" {
				out = append(out, LintIssue{Severity: "warning", Path: path, Message: "missing type"})
			}
			multi := strings.HasPrefix(f.Type, "u16") || strings.HasPrefix(f.Type, "u32") ||
				strings.HasPrefix(f.Type, "u64") || strings.HasPrefix(f.Type, "i16") ||
				strings.HasPrefix(f.Type, "i32") || strings.HasPrefix(f.Type, "i64")
			if multi && f.Endian == "" && (s.Endian == "" || s.Endian == "mixed") {
				out = append(out, LintIssue{Severity: "warning", Path: path, Message: "multi-byte field without endian"})
			}
			if f.Offset != nil && f.Length > 0 {
				spans = append(spans, span{name: path, s: *f.Offset, e: *f.Offset + f.Length})
			}
			if f.Confidence == "Low" || f.Confidence == "Insufficient" || f.Confidence == "Unknown" {
				out = append(out, LintIssue{Severity: "info", Path: path, Message: "low/unknown confidence — treat as draft"})
			}
			if len(f.Children) > 0 {
				walk(path+".", f.Children)
			}
		}
	}
	walk("", s.Fields)
	for i := 0; i < len(spans); i++ {
		for j := i + 1; j < len(spans); j++ {
			a, b := spans[i], spans[j]
			if a.s < b.e && b.s < a.e {
				out = append(out, LintIssue{
					Severity: "warning",
					Path:     a.name + " ∩ " + b.name,
					Message:  fmt.Sprintf("overlapping ranges 0x%02X..0x%02X and 0x%02X..0x%02X", a.s, a.e-1, b.s, b.e-1),
				})
			}
		}
	}
	if len(s.Fields) == 0 {
		out = append(out, LintIssue{Severity: "warning", Path: s.Name, Message: "no fields defined"})
	}
	return out
}
