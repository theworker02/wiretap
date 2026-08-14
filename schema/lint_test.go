package schema_test

import (
	"testing"

	"github.com/theworker02/wiretap/schema"
)

func TestLintOverlapAndEndian(t *testing.T) {
	off0, off1 := 0, 1
	s := &schema.Schema{
		Name: "demo",
		Fields: []schema.Field{
			{Name: "a", Type: "u16", Offset: &off0, Length: 2},
			{Name: "b", Type: "u8", Offset: &off1, Length: 1},
		},
	}
	issues := schema.Lint(s)
	if len(issues) == 0 {
		t.Fatal("expected lint issues for overlap/endian")
	}
	foundWarning := false
	for _, i := range issues {
		if i.Severity == "warning" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("expected warning severity, got %#v", issues)
	}
}

func TestLintCleanMinimal(t *testing.T) {
	off := 0
	s := &schema.Schema{
		Name:    "ok",
		Version: "1",
		Endian:  "be",
		Fields: []schema.Field{
			{Name: "magic", Type: "u8", Offset: &off, Length: 1, Endian: "be"},
		},
	}
	if errs := schema.Validate(s); len(errs) != 0 {
		t.Fatalf("validate: %v", errs)
	}
	_ = schema.Lint(s)
}
