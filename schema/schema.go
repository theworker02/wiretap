package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// Schema is a nested protocol schema AST.
type Schema struct {
	Name    string  `yaml:"name" json:"name"`
	Version string  `yaml:"version,omitempty" json:"version,omitempty"`
	Endian  string  `yaml:"endian,omitempty" json:"endian,omitempty"` // le|be|mixed
	Fields  []Field `yaml:"fields" json:"fields"`
	Notes   string  `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// Field is one schema node (may contain children for nested structures).
type Field struct {
	Name        string         `yaml:"name" json:"name"`
	Offset      *int           `yaml:"offset,omitempty" json:"offset,omitempty"`
	Length      int            `yaml:"length,omitempty" json:"length,omitempty"`
	Type        string         `yaml:"type" json:"type"` // u8,u16,u32,u64,i8,...,bytes,string,bitfield,checksum,struct,array
	Endian      string         `yaml:"endian,omitempty" json:"endian,omitempty"`
	Encoding    string         `yaml:"encoding,omitempty" json:"encoding,omitempty"`
	Value       string         `yaml:"value,omitempty" json:"value,omitempty"` // expected constant hex
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Confidence  string         `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Evidence    string         `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	Children    []Field        `yaml:"fields,omitempty" json:"fields,omitempty"`
	Meta        map[string]any `yaml:"meta,omitempty" json:"meta,omitempty"`
}

// MarshalYAML serializes a schema.
func MarshalYAML(s *Schema) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# Wiretap schema\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalYAML parses a schema from YAML.
func UnmarshalYAML(b []byte) (*Schema, error) {
	var s Schema
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", wt.ErrSchemaInvalid, err)
	}
	if s.Name == "" {
		return nil, fmt.Errorf("%w: name required", wt.ErrSchemaInvalid)
	}
	return &s, nil
}

// MarshalJSON serializes a schema as indented JSON.
func MarshalJSON(s *Schema) ([]byte, error) {
	if s == nil {
		return nil, wt.ErrSchemaInvalid
	}
	return json.MarshalIndent(s, "", "  ")
}

// UnmarshalJSON parses a schema from JSON.
func UnmarshalJSON(b []byte) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", wt.ErrSchemaInvalid, err)
	}
	if s.Name == "" {
		return nil, fmt.Errorf("%w: name required", wt.ErrSchemaInvalid)
	}
	return &s, nil
}

// UnmarshalAuto parses JSON or YAML. format is json|yaml|"" (auto).
func UnmarshalAuto(b []byte, format string) (*Schema, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json":
		return UnmarshalJSON(b)
	case "yaml", "yml":
		return UnmarshalYAML(b)
	case "":
		trim := bytes.TrimSpace(b)
		if len(trim) > 0 && trim[0] == '{' {
			if s, err := UnmarshalJSON(b); err == nil {
				return s, nil
			}
		}
		return UnmarshalYAML(b)
	default:
		return nil, fmt.Errorf("%w: unknown schema format %q", wt.ErrUnsupportedFmt, format)
	}
}

// LoadFile loads a schema from path, selecting codec by extension or format override.
func LoadFile(path string, format string) (*Schema, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if format == "" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			format = "json"
		case ".yaml", ".yml":
			format = "yaml"
		}
	}
	return UnmarshalAuto(b, format)
}

// Validate checks structural consistency of the schema AST.
func Validate(s *Schema) []error {
	var errs []error
	if s == nil {
		return []error{fmt.Errorf("%w: nil schema", wt.ErrSchemaInvalid)}
	}
	if s.Name == "" {
		errs = append(errs, fmt.Errorf("%w: name required", wt.ErrSchemaInvalid))
	}
	seen := map[string]struct{}{}
	var walk func(fields []Field, path string)
	walk = func(fields []Field, path string) {
		for i, f := range fields {
			p := path + "/" + f.Name
			if f.Name == "" {
				errs = append(errs, fmt.Errorf("%w: field[%d] missing name at %s", wt.ErrSchemaInvalid, i, path))
				continue
			}
			if _, ok := seen[p]; ok {
				errs = append(errs, fmt.Errorf("%w: duplicate field path %s", wt.ErrSchemaInvalid, p))
			}
			seen[p] = struct{}{}
			if f.Type == "" {
				errs = append(errs, fmt.Errorf("%w: field %s missing type", wt.ErrSchemaInvalid, p))
			}
			if f.Length < 0 {
				errs = append(errs, fmt.Errorf("%w: field %s negative length", wt.ErrSchemaInvalid, p))
			}
			if f.Type == "struct" && len(f.Children) == 0 {
				errs = append(errs, fmt.Errorf("%w: struct %s has no children (nested fields required)", wt.ErrSchemaInvalid, p))
			}
			if f.Type == "array" && len(f.Children) == 0 && f.Length == 0 {
				errs = append(errs, fmt.Errorf("%w: array %s needs element fields (fields:) or positive element length", wt.ErrSchemaInvalid, p))
			}
			if f.Type == "checksum" && f.Length != 1 && f.Length != 2 && f.Length != 4 {
				errs = append(errs, fmt.Errorf("%w: checksum %s length must be 1, 2, or 4 (got %d)", wt.ErrSchemaInvalid, p, f.Length))
			}
			if f.Type == "array" {
				if _, ok := asInt(f.Meta["element_size"]); !ok && f.Length <= 0 && len(f.Children) == 0 {
					errs = append(errs, fmt.Errorf("%w: array %s missing meta.element_size (or children)", wt.ErrSchemaInvalid, p))
				}
			}
			if len(f.Children) > 0 {
				walk(f.Children, p)
			}
		}
	}
	walk(s.Fields, "")
	return errs
}

type span struct {
	off, len int
	priority int
	score    float64
	field    Field
}

func kindPriority(kind, typ string) int {
	switch kind {
	case "checksum":
		return 100
	case "length":
		return 90
	case "counter":
		return 80
	case "timestamp":
		return 70
	case "array":
		return 65
	case "string":
		return 60
	case "bitfield":
		return 50
	case "integer":
		return 40
	case "pattern":
		return 20
	}
	switch typ {
	case "checksum":
		return 100
	case "array", "struct":
		return 65
	}
	return 10
}

func confScore(level string, score float64) float64 {
	base := score
	switch wt.ConfidenceLevel(level) {
	case wt.ConfidenceHigh:
		base += 2
	case wt.ConfidenceMedium:
		base += 1
	}
	return base
}

// inferEligible gates schema fields: High always; Medium only strong structural kinds.
func inferEligible(h wt.Hypothesis) bool {
	switch h.Confidence.Level {
	case wt.ConfidenceHigh:
		return true
	case wt.ConfidenceMedium:
		if h.Confidence.Score < 0.8 {
			return false
		}
		switch h.Kind {
		case "checksum", "length", "array", "counter", "typefield", "string", "timestamp", "tlv":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// InferFromHypotheses builds a schema from high-confidence hypotheses + constants.
// Prefers typed fields over opaque ints, deconflicts overlaps, and may emit nested header structs / arrays.
func InferFromHypotheses(name string, constants []struct {
	Start, End int
	Value      byte
}, hyps []wt.Hypothesis) *Schema {
	s := &Schema{Name: name, Version: "0.1.0", Endian: "mixed", Notes: "Inferred — competing hypotheses may remain unresolved"}
	var spans []span
	for _, c := range constants {
		off := c.Start
		length := c.End - c.Start
		if length <= 0 {
			continue
		}
		spans = append(spans, span{off, length, 15, 1, Field{
			Name: fmt.Sprintf("const_%d", off), Offset: &off, Length: length,
			Type: "bytes", Value: fmt.Sprintf("%x", bytesRepeat(c.Value, length)),
			Description: "constant region", Confidence: string(wt.ConfidenceHigh),
			Evidence: "identical across messages",
		}})
	}
	for _, h := range hyps {
		// Prefer High; admit Medium only for structural kinds with a raised score bar
		// so Medium integer/pattern spam does not flood inferred schemas.
		if !inferEligible(h) {
			continue
		}
		off := h.Offset
		if off < 0 {
			continue
		}
		if h.Kind == "array" {
			spans = append(spans, spanFromArray(h)...)
			continue
		}
		t := mapKind(h)
		endian, _ := h.Params["endian"].(string)
		f := Field{
			Name: sanitizeName(h.Kind, off), Offset: &off, Length: h.Length,
			Type: t, Endian: endian, Description: h.Description,
			Confidence: string(h.Confidence.Level), Evidence: summarizeEv(h),
			Meta: h.Params,
		}
		spans = append(spans, span{off, h.Length, kindPriority(h.Kind, t), confScore(string(h.Confidence.Level), h.Confidence.Score), f})
	}

	chosen := deconflict(spans)
	s.Fields = nestHeader(chosen)
	return s
}

func spanFromArray(h wt.Hypothesis) []span {
	elem, _ := asInt(h.Params["element_size"])
	if elem <= 0 {
		elem = h.Length
	}
	if elem <= 0 {
		elem = 4
	}
	hdr, _ := asInt(h.Params["header_size"])
	arrOff, ok := asInt(h.Params["array_offset"])
	if !ok {
		arrOff = h.Offset
	}
	countOff, hasCount := asInt(h.Params["count_offset"])
	cw, _ := asInt(h.Params["count_width"])
	endian, _ := h.Params["endian"].(string)
	var out []span
	if hasCount && cw > 0 {
		coff := countOff
		out = append(out, span{coff, cw, 90, confScore(string(h.Confidence.Level), h.Confidence.Score), Field{
			Name: sanitizeName("count", coff), Offset: &coff, Length: cw, Type: fmt.Sprintf("u%d", cw*8),
			Endian: endian, Description: "array count", Confidence: string(h.Confidence.Level),
			Evidence: summarizeEv(h), Meta: map[string]any{"role": "array_count"},
		}})
	}
	aoff := arrOff
	elemField := Field{Name: "elem", Type: "bytes", Length: elem, Description: "repeated element"}
	out = append(out, span{aoff, elem, 65, confScore(string(h.Confidence.Level), h.Confidence.Score), Field{
		Name: sanitizeName("array", aoff), Offset: &aoff, Length: elem, Type: "array",
		Description: h.Description, Confidence: string(h.Confidence.Level), Evidence: summarizeEv(h),
		Children: []Field{elemField},
		Meta: map[string]any{
			"element_size": elem, "header_size": hdr, "count_offset": countOff, "count_width": cw, "endian": endian,
		},
	}})
	return out
}

func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	default:
		return 0, false
	}
}

func deconflict(spans []span) []Field {
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].priority != spans[j].priority {
			return spans[i].priority > spans[j].priority
		}
		if spans[i].score != spans[j].score {
			return spans[i].score > spans[j].score
		}
		if spans[i].off != spans[j].off {
			return spans[i].off < spans[j].off
		}
		return spans[i].field.Name < spans[j].field.Name
	})
	occupied := map[int]bool{}
	var chosen []span
	for _, sp := range spans {
		if sp.len <= 0 {
			continue
		}
		overlap := false
		for i := sp.off; i < sp.off+sp.len; i++ {
			if occupied[i] {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}
		for i := sp.off; i < sp.off+sp.len; i++ {
			occupied[i] = true
		}
		chosen = append(chosen, sp)
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].off < chosen[j].off })
	fields := make([]Field, len(chosen))
	for i, sp := range chosen {
		fields[i] = sp.field
	}
	return fields
}

func nestHeader(fields []Field) []Field {
	if len(fields) < 2 {
		return fields
	}
	// Group a tight leading header (constants + early control fields) only.
	boundary := 0
	hasConst, hasLen := false, false
	end := 0
	for i, f := range fields {
		if f.Offset == nil {
			break
		}
		off := *f.Offset
		if off > 12 || f.Type == "array" || f.Type == "checksum" || f.Type == "string" {
			break
		}
		if off > end+1 && i > 0 {
			// gap — stop nesting
			break
		}
		flen := f.Length
		if flen <= 0 {
			flen = 1
		}
		if off+flen > 16 {
			break
		}
		if strings.HasPrefix(f.Name, "const_") || f.Value != "" {
			hasConst = true
		}
		if strings.Contains(f.Name, "length") || strings.Contains(f.Description, "length") {
			hasLen = true
		}
		if off+flen > end {
			end = off + flen
		}
		boundary = i + 1
		if boundary >= 6 {
			break
		}
	}
	if boundary < 2 || !(hasConst && hasLen) {
		return fields
	}
	headerChildren := fields[:boundary]
	rest := fields[boundary:]
	hdrOff := *headerChildren[0].Offset
	header := Field{
		Name: "header", Offset: &hdrOff, Length: end - hdrOff, Type: "struct",
		Description: "inferred header group", Children: headerChildren,
	}
	return append([]Field{header}, rest...)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func mapKind(h wt.Hypothesis) string {
	switch h.Kind {
	case "integer", "counter", "length", "timestamp":
		w := h.Length
		signed, _ := h.Params["signed"].(bool)
		if signed {
			return fmt.Sprintf("i%d", w*8)
		}
		return fmt.Sprintf("u%d", w*8)
	case "checksum":
		return "checksum"
	case "string":
		return "string"
	case "bitfield":
		return "bitfield"
	case "array":
		return "array"
	case "pattern":
		return "bytes"
	default:
		return "bytes"
	}
}

func sanitizeName(kind string, off int) string {
	k := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, strings.ToLower(kind))
	return fmt.Sprintf("%s_%d", k, off)
}

func summarizeEv(h wt.Hypothesis) string {
	parts := make([]string, 0, len(h.Confidence.Evidence))
	for _, e := range h.Confidence.Evidence {
		parts = append(parts, e.Description)
	}
	return strings.Join(parts, "; ")
}

func exportName(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	out := b.String()
	if out == "" {
		return "Field"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "F" + out
	}
	return out
}

func goType(f Field) string {
	switch f.Type {
	case "u8", "bitfield":
		return "uint8"
	case "u16":
		return "uint16"
	case "u32":
		return "uint32"
	case "u64":
		return "uint64"
	case "i8":
		return "int8"
	case "i16":
		return "int16"
	case "i32":
		return "int32"
	case "i64":
		return "int64"
	case "string":
		return "string"
	case "checksum":
		switch f.Length {
		case 1:
			return "uint8"
		case 2:
			return "uint16"
		case 4:
			return "uint32"
		default:
			return "[]byte"
		}
	default:
		return "[]byte"
	}
}

func defaultLen(t string) int {
	switch t {
	case "u8", "i8", "bitfield":
		return 1
	case "u16", "i16":
		return 2
	case "u32", "i32":
		return 4
	case "u64", "i64":
		return 8
	default:
		return 0
	}
}

// FormatCanonical returns canonical YAML or JSON bytes for a schema (stable field order preserved).
// formatOverride is json|yaml|"" (inferred from path extension when empty).
func FormatCanonical(s *Schema, path, formatOverride string) ([]byte, error) {
	if s == nil {
		return nil, wt.ErrSchemaInvalid
	}
	format := strings.ToLower(strings.TrimSpace(formatOverride))
	if format == "" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			format = "json"
		default:
			format = "yaml"
		}
	}
	switch format {
	case "json":
		return MarshalJSON(s)
	case "yaml", "yml":
		return MarshalYAML(s)
	default:
		return nil, fmt.Errorf("%w: format must be json|yaml", wt.ErrUnsupportedFmt)
	}
}
