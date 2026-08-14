package visualize_test

import (
	"testing"

	"github.com/theworker02/wiretap/internal/visualize"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
	"github.com/theworker02/wiretap/schema"
)

func TestRenderSVGSmoke(t *testing.T) {
	off := 0
	s := &schema.Schema{Name: "t", Fields: []schema.Field{
		{Name: "magic", Offset: &off, Length: 2, Type: "u16", Confidence: "High"},
	}}
	res := &wt.Result{MaxLength: 16, Hypotheses: []wt.Hypothesis{
		{ID: "h1", Kind: "length", Offset: 4, Length: 2, Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 0.9}},
	}}
	svg, err := visualize.RenderSVG(res, s, visualize.Options{Title: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(svg) < 50 || string(svg[:4]) != "<svg" {
		t.Fatalf("bad svg: %s", svg[:min(40, len(svg))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
