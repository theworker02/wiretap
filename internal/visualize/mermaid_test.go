package visualize_test

import (
	"strings"
	"testing"

	"github.com/theworker02/wiretap/internal/visualize"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

func TestMermaidFromSchema(t *testing.T) {
	off0, off2 := 0, 2
	sch := &schema.Schema{
		Name: "demo",
		Fields: []schema.Field{
			{Name: "magic", Offset: &off0, Length: 2, Type: "u16", Confidence: "High"},
			{Name: "type", Offset: &off2, Length: 1, Type: "u8", Confidence: "Medium"},
		},
	}
	s, err := visualize.RenderMermaid(nil, sch)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "flowchart LR") || !strings.Contains(s, "magic") {
		t.Fatalf("unexpected mermaid: %s", s)
	}
}

func TestMermaidFromReport(t *testing.T) {
	res := &wt.Result{Hypotheses: []wt.Hypothesis{
		{ID: "len", Kind: "length", Offset: 4, Length: 2, Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 1}},
	}}
	s, err := visualize.RenderMermaid(res, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "length") {
		t.Fatalf("missing length: %s", s)
	}
}
