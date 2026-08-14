package inference_test

import (
	"testing"

	"github.com/theworker02/wiretap/internal/inference"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestCompeteDropsMediumSpamUnderHigh(t *testing.T) {
	hyps := []wt.Hypothesis{
		{ID: "len", Kind: "length", Offset: 4, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 1.0}},
		{ID: "i4", Kind: "integer", Offset: 4, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceMedium, Score: 0.7}},
		{ID: "pat", Kind: "pattern", Offset: 4, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceMedium, Score: 0.65}},
		{ID: "ctr", Kind: "counter", Offset: 8, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 0.95}},
	}
	out := inference.CompeteHypotheses(hyps, 32)
	ids := map[string]bool{}
	for _, h := range out {
		ids[h.ID] = true
	}
	if !ids["len"] || !ids["ctr"] {
		t.Fatalf("expected structural winners kept: %v", ids)
	}
	if ids["i4"] || ids["pat"] {
		t.Fatalf("expected Medium spam pruned: %v", ids)
	}
}

func TestCompeteCollapsesOverlappingLengthsAndNested(t *testing.T) {
	hyps := []wt.Hypothesis{
		{ID: "len4", Kind: "length", Offset: 4, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 1.0}},
		{ID: "len5", Kind: "length", Offset: 5, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 1.0}},
		{ID: "nest", Kind: "nested", Offset: 0, Length: 20,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 1.0}},
		{ID: "ctr6", Kind: "counter", Offset: 6, Length: 2,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 0.95}},
		{ID: "ctr7", Kind: "counter", Offset: 7, Length: 1,
			Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 0.95}},
	}
	out := inference.CompeteHypotheses(hyps, 32)
	ids := map[string]bool{}
	for _, h := range out {
		ids[h.ID] = true
	}
	if !ids["len4"] {
		t.Fatalf("expected primary length kept: %v", ids)
	}
	if ids["len5"] {
		t.Fatalf("expected overlapping length pruned: %v", ids)
	}
	if ids["nest"] {
		t.Fatalf("expected nested pruned under structure: %v", ids)
	}
	if !ids["ctr6"] {
		t.Fatalf("expected outer counter kept: %v", ids)
	}
	if ids["ctr7"] {
		t.Fatalf("expected contained counter pruned: %v", ids)
	}
}
