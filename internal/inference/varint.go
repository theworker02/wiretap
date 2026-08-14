package inference

import (
	"context"
	"fmt"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// VarintPass detects protobuf-like varints / wire-type candidates with low default confidence.
// It never asserts "this is protobuf" without repeated structural confirmation.
type VarintPass struct{}

func (VarintPass) Name() string { return "varint" }

func (VarintPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if in.Budget == wt.BudgetQuick {
		return out, nil // optional; skip on quick
	}
	ds := in.Dataset
	if ds == nil || ds.Len() < 2 {
		return out, nil
	}
	minLen := ds.MinLen()
	if minLen < 2 {
		return out, nil
	}

	var hyps []wt.Hypothesis
	maxOff := 32
	if in.Budget == wt.BudgetExhaustive {
		maxOff = 64
	}
	for off := 0; off < minLen && off < maxOff; off++ {
		select {
		case <-ctx.Done():
			out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
			return out, ctx.Err()
		default:
		}
		valid, total, avgLen, tagLike := scoreVarints(ds, off)
		if total < 2 || valid*2 < total { // ≥50% parse as varints
			continue
		}
		ratio := float64(valid) / float64(total)
		ev := []wt.EvidenceItem{
			{Kind: "observation", Description: "protobuf-like varint candidate (not a format claim)", Weight: 0.8, Metric: "parse_ratio", Value: ratio},
		}
		if avgLen >= 1 && avgLen <= 5 {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "varint lengths in typical range", Weight: 1, Metric: "avg_len", Value: avgLen})
		}
		if tagLike >= 0.7 {
			ev = append(ev, wt.EvidenceItem{
				Kind: "support", Description: "values look like protobuf field tags (field<<3|wire)", Weight: 1.5, Metric: "tag_like_ratio", Value: tagLike,
			})
			ev = append(ev, wt.EvidenceItem{
				Kind: "observation", Description: "Insufficient evidence to claim protobuf — candidate only", Weight: 0.2,
			})
		} else {
			ev = append(ev, wt.EvidenceItem{
				Kind: "contradict", Description: "varints parse but lack repeated protobuf tag structure", Weight: 0.5,
			})
		}
		// Require at least Low; High only with strong tag evidence across messages
		conf := wt.DeriveConfidence(ev)
		if conf.Level == wt.ConfidenceUnknown || conf.Level == wt.ConfidenceInsufficient {
			continue
		}
		// Cap confidence: without strong confirmation stay ≤ Medium
		if tagLike < 0.9 && conf.Level == wt.ConfidenceHigh {
			conf.Level = wt.ConfidenceMedium
			conf.Notes = "capped: protobuf not confirmed"
		}
		kind := "varint"
		if tagLike >= 0.7 {
			kind = "protobuf_like"
		}
		hyps = append(hyps, wt.Hypothesis{
			ID: fmt.Sprintf("varint_o%d", off), Kind: kind, Offset: off, Length: int(avgLen + 0.5),
			Description: "protobuf-like varint/wire-type candidate (heuristic; not a format claim)",
			Params: map[string]any{
				"parse_ratio": ratio, "avg_len": avgLen, "tag_like_ratio": tagLike,
			},
			Confidence: conf, Status: "hypothesis",
		})
	}
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func scoreVarints(ds *wt.Dataset, off int) (valid, total int, avgLen, tagLike float64) {
	sumLen := 0.0
	tagOK := 0
	nParsed := 0
	for _, m := range ds.Messages {
		if off >= len(m.Data) {
			continue
		}
		total++
		v, n, ok := readVarint(m.Data[off:])
		if !ok || n < 1 {
			continue
		}
		valid++
		sumLen += float64(n)
		nParsed++
		// protobuf key: field_number << 3 | wire_type; wire_type in {0,1,2,5}
		wt := v & 0x7
		field := v >> 3
		if (wt == 0 || wt == 1 || wt == 2 || wt == 5) && field >= 1 && field <= 100 {
			tagOK++
		}
	}
	if nParsed > 0 {
		avgLen = sumLen / float64(nParsed)
		tagLike = float64(tagOK) / float64(nParsed)
	}
	return valid, total, avgLen, tagLike
}

func readVarint(b []byte) (uint64, int, bool) {
	var x uint64
	var s uint
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if c < 0x80 {
			if i == 9 && c > 1 {
				return 0, 0, false
			}
			return x | uint64(c)<<s, i + 1, true
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0, false
}
