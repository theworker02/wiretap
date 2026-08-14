package inference

import (
	"context"
	"fmt"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// NestedPass proposes nested header/payload groupings when length + array evidence aligns.
// Less conservative than requiring exhaustive proof: Medium confidence when length and
// trailing payload regions co-occur with array/count hypotheses.
type NestedPass struct{}

func (NestedPass) Name() string { return "nested" }

func (NestedPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if !in.Config.EnableStructured || in.Dataset == nil || in.Dataset.Len() < 2 {
		return out, nil
	}
	ds := in.Dataset
	minLen := ds.MinLen()
	if minLen < 8 {
		return out, nil
	}

	var lengthHyps, arrayHyps []wt.Hypothesis
	for _, h := range in.Hypotheses {
		switch h.Kind {
		case "length":
			if h.Confidence.Level == wt.ConfidenceHigh || h.Confidence.Level == wt.ConfidenceMedium {
				lengthHyps = append(lengthHyps, h)
			}
		case "array":
			if h.Confidence.Level == wt.ConfidenceHigh || h.Confidence.Level == wt.ConfidenceMedium || h.Confidence.Level == wt.ConfidenceLow {
				arrayHyps = append(arrayHyps, h)
			}
		}
	}

	var hyps []wt.Hypothesis

	// Header nesting: constant/low-entropy prefix + length field → header group
	headerEnd := 0
	for _, st := range in.Stats {
		if st.Offset >= 32 {
			break
		}
		if st.ConstantProbability >= 0.9 || st.Unique <= 2 {
			headerEnd = st.Offset + 1
			continue
		}
		break
	}
	if headerEnd >= 2 && headerEnd < minLen {
		ev := []wt.EvidenceItem{
			{Kind: "support", Description: "low-entropy/constant prefix suggests header region", Weight: 2, Metric: "header_end", Value: float64(headerEnd)},
		}
		if len(lengthHyps) > 0 {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "length field hypothesis co-occurs with header", Weight: 2})
		} else {
			ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "no length field confirmed — weaker nesting", Weight: 0.3})
		}
		conf := wt.DeriveConfidence(ev)
		if conf.Level != wt.ConfidenceInsufficient && conf.Level != wt.ConfidenceUnknown {
			hyps = append(hyps, wt.Hypothesis{
				ID: fmt.Sprintf("nest_hdr_0_%d", headerEnd), Kind: "nested",
				Offset: 0, Length: headerEnd,
				Description: fmt.Sprintf("nested header group [0:%d]", headerEnd),
				Params:      map[string]any{"role": "header", "payload_start": headerEnd},
				Confidence:  conf, Status: "hypothesis",
			})
			hyps = append(hyps, wt.Hypothesis{
				ID: fmt.Sprintf("nest_payload_%d", headerEnd), Kind: "nested",
				Offset: headerEnd, Length: minLen - headerEnd,
				Description: fmt.Sprintf("nested payload/body starting at %d", headerEnd),
				Params:      map[string]any{"role": "payload", "header_end": headerEnd},
				Confidence:  conf, Status: "hypothesis",
			})
		}
	}

	// Record groups from array evidence
	for _, ah := range arrayHyps {
		select {
		case <-ctx.Done():
			out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
			return out, ctx.Err()
		default:
		}
		arrOff, _ := asIntParam(ah.Params, "array_offset")
		if arrOff == 0 {
			arrOff = ah.Offset
		}
		elem, _ := asIntParam(ah.Params, "element_size")
		if elem <= 0 {
			elem = ah.Length
		}
		if elem <= 0 || arrOff < 0 {
			continue
		}
		ev := []wt.EvidenceItem{
			{Kind: "support", Description: "array hypothesis provides record grouping", Weight: 2.5},
			{Kind: "observation", Description: fmt.Sprintf("records @%d elemsize=%d", arrOff, elem), Weight: 0.5},
		}
		if len(lengthHyps) > 0 {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "length evidence strengthens nested records", Weight: 1.5})
		}
		hyps = append(hyps, wt.Hypothesis{
			ID: fmt.Sprintf("nest_records_o%d_el%d", arrOff, elem), Kind: "nested",
			Offset: arrOff, Length: elem,
			Description: fmt.Sprintf("nested record group from array evidence (elem=%d @%d)", elem, arrOff),
			Params: map[string]any{
				"role": "records", "element_size": elem, "array_offset": arrOff,
				"from_array": ah.ID,
			},
			Confidence: wt.DeriveConfidence(ev), Status: "hypothesis",
		})
	}

	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func asIntParam(m map[string]any, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	default:
		return 0, false
	}
}
