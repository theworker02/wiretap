// Package samplepass shows how to implement an external-style Wiretap Pass.
// Copy this pattern into your own module and register via wiretap.RegisterPass.
package samplepass

import (
	"context"
	"fmt"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func init() {
	wt.RegisterPass(MagicTHPass{})
}

// MagicTHPass looks for ASCII "TH" at offset 0 across messages.
type MagicTHPass struct{}

func (MagicTHPass) Name() string { return "example_magic_th" }

func (MagicTHPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if in.Dataset == nil || in.Dataset.Len() == 0 {
		return out, nil
	}
	ok, total := 0, 0
	for _, m := range in.Dataset.Messages {
		if len(m.Data) < 2 {
			continue
		}
		total++
		if m.Data[0] == 'T' && m.Data[1] == 'H' {
			ok++
		}
	}
	if total < 2 || ok*10 < total*9 {
		return out, nil
	}
	ev := []wt.EvidenceItem{{
		Kind: "support", Description: "constant ASCII TH magic at offset 0",
		Weight: 3, Metric: "match_ratio", Value: float64(ok) / float64(total),
	}}
	out.Hypotheses = append(out.Hypotheses, wt.Hypothesis{
		ID: "example_magic_th", Kind: "pattern", Offset: 0, Length: 2,
		Description: fmt.Sprintf("example plugin: TH magic (%d/%d messages)", ok, total),
		Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
	})
	return out, nil
}
