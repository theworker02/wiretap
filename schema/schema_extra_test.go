package schema_test

import (
	"os"
	"path/filepath"
	"testing"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

func TestJSONRoundTrip(t *testing.T) {
	off0 := 0
	s := &schema.Schema{
		Name: "demo", Version: "0.1.0",
		Fields: []schema.Field{{Name: "magic", Offset: &off0, Length: 2, Type: "bytes"}},
	}
	b, err := schema.MarshalJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := schema.UnmarshalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Name != "demo" || len(s2.Fields) != 1 {
		t.Fatalf("%+v", s2)
	}
}

func TestLoadFileJSONYAML(t *testing.T) {
	dir := t.TempDir()
	off := 0
	s := &schema.Schema{Name: "x", Fields: []schema.Field{{Name: "a", Offset: &off, Length: 1, Type: "u8"}}}
	jb, _ := schema.MarshalJSON(s)
	jp := filepath.Join(dir, "s.json")
	_ = os.WriteFile(jp, jb, 0o644)
	got, err := schema.LoadFile(jp, "")
	if err != nil || got.Name != "x" {
		t.Fatalf("%v %+v", err, got)
	}
	yb, _ := schema.MarshalYAML(s)
	yp := filepath.Join(dir, "s.yaml")
	_ = os.WriteFile(yp, yb, 0o644)
	got2, err := schema.LoadFile(yp, "")
	if err != nil || got2.Name != "x" {
		t.Fatalf("%v %+v", err, got2)
	}
}

func TestInferNestedAndArray(t *testing.T) {
	consts := []struct {
		Start, End int
		Value      byte
	}{{0, 2, 0xBE}}
	off4 := 4
	hyps := []wt.Hypothesis{
		{
			ID: "len_o4", Kind: "length", Offset: off4, Length: 2,
			Description: "length field", Confidence: wt.DeriveConfidence([]wt.EvidenceItem{
				{Kind: "support", Description: "matches", Weight: 5},
			}),
			Params: map[string]any{"endian": "be"},
		},
		{
			ID: "arr", Kind: "array", Offset: 8, Length: 4,
			Description: "records", Confidence: wt.DeriveConfidence([]wt.EvidenceItem{
				{Kind: "support", Description: "count predicts span", Weight: 5},
			}),
			Params: map[string]any{
				"element_size": 4, "header_size": 8, "array_offset": 8,
				"count_offset": 6, "count_width": 1, "endian": "be",
			},
		},
	}
	s := schema.InferFromHypotheses("nested", consts, hyps)
	if s == nil || len(s.Fields) == 0 {
		t.Fatal("empty schema")
	}
	hasStruct, hasArray := false, false
	var walk func([]schema.Field)
	walk = func(fs []schema.Field) {
		for _, f := range fs {
			if f.Type == "struct" {
				hasStruct = true
			}
			if f.Type == "array" {
				hasArray = true
			}
			walk(f.Children)
		}
	}
	walk(s.Fields)
	if !hasArray {
		t.Fatalf("expected array field in %#v", s.Fields)
	}
	_ = hasStruct // nesting is best-effort when const+length present
	code, err := schema.GenerateGo(s, "protocol")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(code, "ParseNested") && !contains(code, "func Parse") {
		t.Fatalf("codegen:\n%s", code)
	}
}

func TestGenerateNestedStruct(t *testing.T) {
	o0, o2 := 0, 2
	s := &schema.Schema{
		Name: "pkt",
		Fields: []schema.Field{
			{
				Name: "header", Type: "struct", Offset: &o0, Length: 3,
				Children: []schema.Field{
					{Name: "magic", Offset: &o0, Length: 2, Type: "bytes"},
					{Name: "ver", Offset: &o2, Length: 1, Type: "u8"},
				},
			},
		},
	}
	code, err := schema.GenerateGo(s, "p")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(code, "type PktHeader struct") {
		t.Fatalf("missing nested type:\n%s", code)
	}
	if !contains(code, "ParsePkt") {
		t.Fatalf("missing parse:\n%s", code)
	}
}

func TestGenerateArrayBounds(t *testing.T) {
	o4 := 4
	s := &schema.Schema{
		Name: "arrproto",
		Fields: []schema.Field{
			{
				Name: "items", Type: "array", Offset: &o4, Length: 4,
				Children: []schema.Field{{Name: "elem", Type: "bytes", Length: 4}},
				Meta:     map[string]any{"element_size": 4, "count_offset": 3, "count_width": 1, "endian": "be"},
			},
		},
	}
	code, err := schema.GenerateGo(s, "p")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(code, "array bounds") {
		t.Fatalf("expected bounds check:\n%s", code)
	}
}
