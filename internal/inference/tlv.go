package inference

import (
	"context"
	"fmt"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// TLVPass detects simple repeating Type-Length-Value patterns.
type TLVPass struct{}

func (TLVPass) Name() string { return "tlv" }

func (TLVPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	ds := in.Dataset
	if ds == nil || ds.Len() < 2 {
		return out, nil
	}
	minLen := ds.MinLen()
	if minLen < 4 {
		return out, nil
	}

	type spec struct {
		tW, lW int
		endian string
	}
	specs := []spec{
		{1, 1, "be"},
		{1, 2, "be"},
		{1, 2, "le"},
		{2, 2, "be"},
		{2, 2, "le"},
	}
	if in.Budget == wt.BudgetQuick {
		specs = specs[:2]
	}

	var hyps []wt.Hypothesis
	starts := []int{0, 2, 4, 6, 8}
	if in.Budget == wt.BudgetExhaustive {
		for i := 0; i < 16; i++ {
			starts = append(starts, i)
		}
	}

	seen := map[string]bool{}
	for _, sp := range specs {
		for _, start := range starts {
			select {
			case <-ctx.Done():
				out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
				return out, ctx.Err()
			default:
			}
			if start+sp.tW+sp.lW >= minLen {
				continue
			}
			ok, total, avgTLVs := scoreTLV(ds, start, sp.tW, sp.lW, sp.endian)
			if total < 2 || ok*10 < total*8 { // ≥80%
				continue
			}
			ratio := float64(ok) / float64(total)
			id := fmt.Sprintf("tlv_o%d_t%d_l%d_%s", start, sp.tW, sp.lW, sp.endian)
			if seen[id] {
				continue
			}
			seen[id] = true
			ev := []wt.EvidenceItem{
				{Kind: "support", Description: "repeating TLV walk consumes message body", Weight: 3, Metric: "match_ratio", Value: ratio},
			}
			if avgTLVs >= 2 {
				ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "multiple TLV records per message", Weight: 2, Metric: "avg_tlvs", Value: avgTLVs})
			} else {
				ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "often a single TLV — weaker pattern", Weight: 0.3})
			}
			hyps = append(hyps, wt.Hypothesis{
				ID: id, Kind: "tlv", Offset: start, Length: sp.tW + sp.lW,
				Description: fmt.Sprintf("TLV pattern candidate (T=%d L=%d %s) @%d", sp.tW, sp.lW, sp.endian, start),
				Params: map[string]any{
					"type_width": sp.tW, "length_width": sp.lW, "endian": sp.endian,
					"avg_tlvs": avgTLVs,
				},
				Confidence: wt.DeriveConfidence(ev), Status: "hypothesis",
			})
		}
	}
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func scoreTLV(ds *wt.Dataset, start, tW, lW int, endian string) (ok, total int, avg float64) {
	sumTLV := 0.0
	nOK := 0
	for _, m := range ds.Messages {
		if start >= len(m.Data) {
			continue
		}
		total++
		off := start
		count := 0
		good := true
		for off+tW+lW <= len(m.Data) {
			_ = m.Data[off : off+tW] // type
			lnU, rok := readU(m.Data[off+tW:off+tW+lW], endian)
			if !rok {
				good = false
				break
			}
			ln := int(lnU)
			if ln < 0 || ln > len(m.Data) || off+tW+lW+ln > len(m.Data) {
				good = false
				break
			}
			off += tW + lW + ln
			count++
			if count > 64 {
				good = false
				break
			}
			// allow trailing checksum 0–4 bytes
			rem := len(m.Data) - off
			if rem == 0 || rem == 2 || rem == 4 {
				break
			}
			if rem < tW+lW {
				if rem > 0 && rem <= 4 {
					break // trailer
				}
				good = false
				break
			}
		}
		if good && count >= 1 && (off == len(m.Data) || len(m.Data)-off <= 4) {
			ok++
			sumTLV += float64(count)
			nOK++
		}
	}
	if nOK > 0 {
		avg = sumTLV / float64(nOK)
	}
	return ok, total, avg
}
