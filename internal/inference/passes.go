package inference

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func prune(hyps []wt.Hypothesis, max int) []wt.Hypothesis {
	if max <= 0 || len(hyps) <= max {
		return hyps
	}
	sort.SliceStable(hyps, func(i, j int) bool {
		if hyps[i].Confidence.Score == hyps[j].Confidence.Score {
			return hyps[i].ID < hyps[j].ID
		}
		return hyps[i].Confidence.Score > hyps[j].Confidence.Score
	})
	return hyps[:max]
}

// --- Integer pass ---

type IntegerPass struct{}

func (IntegerPass) Name() string { return "integers" }

func (IntegerPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if in.Dataset == nil || in.Dataset.Len() == 0 {
		return out, nil
	}
	maxLen := in.Dataset.MaxLen()
	widths := []int{1, 2, 4, 8}
	if in.Budget == wt.BudgetQuick {
		widths = []int{1, 2, 4}
	}
	var hyps []wt.Hypothesis
	for _, width := range widths {
		for off := 0; off+width <= maxLen; off++ {
			select {
			case <-ctx.Done():
				return &wt.PassOutput{Hypotheses: prune(hyps, in.Config.MaxCandidates)}, ctx.Err()
			default:
			}
			for _, endian := range []string{"le", "be"} {
				if width == 1 && endian == "be" {
					continue
				}
				for _, signed := range []bool{false, true} {
					vals, ok := extractInts(in.Dataset, off, width, endian, signed)
					if !ok || len(vals) < 2 {
						continue
					}
					ev := analyzeIntSeries(vals, off, width, endian, signed)
					if len(ev) == 0 {
						continue
					}
					conf := wt.DeriveConfidence(ev)
					if conf.Level == wt.ConfidenceUnknown || conf.Level == wt.ConfidenceInsufficient {
						continue
					}
					id := fmt.Sprintf("int_o%d_w%d_%s_%s", off, width, endian, map[bool]string{true: "i", false: "u"}[signed])
					hyps = append(hyps, wt.Hypothesis{
						ID: id, Kind: "integer", Offset: off, Length: width,
						Description: fmt.Sprintf("%s%d %s integer", map[bool]string{true: "i", false: "u"}[signed], width*8, endian),
						Params: map[string]any{
							"endian": endian, "signed": signed, "width": width,
						},
						Confidence: conf, Status: "hypothesis",
					})
				}
			}
		}
	}
	// Endianness contextual evidence: prefer endian that shows more monotonic fields
	hyps = annotateEndianCompetition(hyps)
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func extractInts(ds *wt.Dataset, off, width int, endian string, signed bool) ([]float64, bool) {
	vals := make([]float64, 0, ds.Len())
	for _, m := range ds.Messages {
		if off+width > len(m.Data) {
			continue
		}
		b := m.Data[off : off+width]
		var u uint64
		switch width {
		case 1:
			u = uint64(b[0])
		case 2:
			if endian == "le" {
				u = uint64(binary.LittleEndian.Uint16(b))
			} else {
				u = uint64(binary.BigEndian.Uint16(b))
			}
		case 4:
			if endian == "le" {
				u = uint64(binary.LittleEndian.Uint32(b))
			} else {
				u = uint64(binary.BigEndian.Uint32(b))
			}
		case 8:
			if endian == "le" {
				u = binary.LittleEndian.Uint64(b)
			} else {
				u = binary.BigEndian.Uint64(b)
			}
		default:
			return nil, false
		}
		var v float64
		if signed {
			shift := 64 - uint(width*8)
			v = float64(int64(u<<shift) >> shift)
		} else {
			v = float64(u)
		}
		vals = append(vals, v)
	}
	return vals, len(vals) > 0
}

func analyzeIntSeries(vals []float64, off, width int, endian string, signed bool) []wt.EvidenceItem {
	var ev []wt.EvidenceItem
	if len(vals) < 2 {
		return nil
	}
	// variance / non-constant
	mean := 0.0
	for _, v := range vals {
		mean += v
	}
	mean /= float64(len(vals))
	var variance float64
	unique := map[float64]struct{}{}
	for _, v := range vals {
		unique[v] = struct{}{}
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(vals))
	if len(unique) == 1 {
		ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "constant integer field", Weight: 0.5, Metric: "unique", Value: 1})
		return ev
	}
	ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "multiple distinct values", Weight: 1, Metric: "unique", Value: float64(len(unique))})

	// monotonicity
	inc, dec := 0, 0
	for i := 1; i < len(vals); i++ {
		if vals[i] > vals[i-1] {
			inc++
		} else if vals[i] < vals[i-1] {
			dec++
		}
	}
	pairs := len(vals) - 1
	if pairs > 0 {
		if float64(inc)/float64(pairs) >= 0.8 {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "mostly increasing", Weight: 2, Metric: "monotonic_inc", Value: float64(inc) / float64(pairs)})
		}
		if float64(dec)/float64(pairs) >= 0.8 {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "mostly decreasing", Weight: 1.5, Metric: "monotonic_dec", Value: float64(dec) / float64(pairs)})
		}
	}

	// length correlation
	return ev
}

func annotateEndianCompetition(hyps []wt.Hypothesis) []wt.Hypothesis {
	// Group by offset+width+signed; mark alternates between le/be
	type key struct {
		off, w int
		signed bool
	}
	groups := map[key][]int{}
	for i, h := range hyps {
		if h.Kind != "integer" {
			continue
		}
		signed, _ := h.Params["signed"].(bool)
		w, _ := h.Params["width"].(int)
		groups[key{h.Offset, w, signed}] = append(groups[key{h.Offset, w, signed}], i)
	}
	for _, idxs := range groups {
		if len(idxs) < 2 {
			continue
		}
		ids := make([]string, 0, len(idxs))
		for _, i := range idxs {
			ids = append(ids, hyps[i].ID)
		}
		for _, i := range idxs {
			hyps[i].Alternates = ids
			hyps[i].Confidence.Evidence = append(hyps[i].Confidence.Evidence, wt.EvidenceItem{
				Kind: "observation", Description: "competing endianness candidates retained", Weight: 0.2,
			})
		}
	}
	return hyps
}

// LengthCorrelationPass correlates integer candidates with message length.
type LengthFieldPass struct{}

func (LengthFieldPass) Name() string { return "length_field" }

func (LengthFieldPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	ds := in.Dataset
	if ds == nil || ds.Len() < 2 {
		return out, nil
	}
	maxLen := ds.MaxLen()
	widths := []int{1, 2, 4}
	var hyps []wt.Hypothesis
	for _, width := range widths {
		for off := 0; off+width <= maxLen && off < 64; off++ {
			select {
			case <-ctx.Done():
				out.Hypotheses = hyps
				return out, ctx.Err()
			default:
			}
			for _, endian := range []string{"be", "le"} {
				if width == 1 && endian == "be" {
					continue
				}
				for _, mode := range []string{"len", "len-C", "remaining"} {
					ev, c := scoreLengthField(ds, off, width, endian, mode)
					if len(ev) == 0 {
						continue
					}
					conf := wt.DeriveConfidence(ev)
					if conf.Level == wt.ConfidenceInsufficient || conf.Level == wt.ConfidenceUnknown {
						continue
					}
					hyps = append(hyps, wt.Hypothesis{
						ID:   fmt.Sprintf("len_o%d_w%d_%s_%s", off, width, endian, mode),
						Kind: "length", Offset: off, Length: width,
						Description: fmt.Sprintf("length field (%s) %s%d", mode, endian, width*8),
						Params:      map[string]any{"endian": endian, "mode": mode, "C": c},
						Confidence:  conf, Status: "hypothesis",
					})
				}
			}
		}
	}
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func scoreLengthField(ds *wt.Dataset, off, width int, endian, mode string) ([]wt.EvidenceItem, int) {
	matches := 0
	total := 0
	bestC := 0
	cScores := map[int]int{}
	for _, m := range ds.Messages {
		if off+width > len(m.Data) {
			continue
		}
		val, ok := readU(m.Data[off:off+width], endian)
		if !ok {
			continue
		}
		total++
		msgLen := len(m.Data)
		switch mode {
		case "len":
			if int(val) == msgLen {
				matches++
			}
			// also try len of payload after field
			if int(val) == msgLen-off-width {
				cScores[0]++
			}
		case "len-C":
			for c := 0; c <= off+width && c < 64; c++ {
				if int(val) == msgLen-c {
					cScores[c]++
				}
			}
		case "remaining":
			if int(val) == msgLen-(off+width) {
				matches++
			}
		}
	}
	if total < 2 {
		return nil, 0
	}
	var ev []wt.EvidenceItem
	switch mode {
	case "len":
		ratio := float64(matches) / float64(total)
		if ratio < 0.9 {
			return nil, 0
		}
		ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "value equals total message length", Weight: 4, Metric: "match_ratio", Value: ratio})
	case "remaining":
		ratio := float64(matches) / float64(total)
		if ratio < 0.9 {
			return nil, 0
		}
		ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "value equals remaining bytes after field", Weight: 4, Metric: "match_ratio", Value: ratio})
	case "len-C":
		best, bestN := 0, 0
		for c, n := range cScores {
			if n > bestN || (n == bestN && c < best) {
				best, bestN = c, n
			}
		}
		ratio := float64(bestN) / float64(total)
		if ratio < 0.9 {
			return nil, 0
		}
		bestC = best
		ev = append(ev, wt.EvidenceItem{Kind: "support", Description: fmt.Sprintf("value equals msgLen-%d", best), Weight: 4, Metric: "match_ratio", Value: ratio})
	}
	return ev, bestC
}

func readU(b []byte, endian string) (uint64, bool) {
	switch len(b) {
	case 1:
		return uint64(b[0]), true
	case 2:
		if endian == "le" {
			return uint64(binary.LittleEndian.Uint16(b)), true
		}
		return uint64(binary.BigEndian.Uint16(b)), true
	case 4:
		if endian == "le" {
			return uint64(binary.LittleEndian.Uint32(b)), true
		}
		return uint64(binary.BigEndian.Uint32(b)), true
	case 8:
		if endian == "le" {
			return binary.LittleEndian.Uint64(b), true
		}
		return binary.BigEndian.Uint64(b), true
	default:
		return 0, false
	}
}

// CounterPass detects monotonically increasing counters with wrap awareness.
type CounterPass struct{}

func (CounterPass) Name() string { return "counters" }

func (CounterPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	ds := in.Dataset
	if ds == nil || ds.Len() < 3 {
		return out, nil
	}
	// Sort by capture time if available, else by ID
	msgs := append([]*wt.Message(nil), ds.Messages...)
	sort.Slice(msgs, func(i, j int) bool {
		if msgs[i].Captured != nil && msgs[j].Captured != nil {
			return msgs[i].Captured.Before(*msgs[j].Captured)
		}
		return msgs[i].ID < msgs[j].ID
	})
	maxLen := ds.MaxLen()
	var hyps []wt.Hypothesis
	for _, width := range []int{1, 2, 4} {
		for off := 0; off+width <= maxLen && off < 128; off++ {
			for _, endian := range []string{"be", "le"} {
				if width == 1 && endian == "be" {
					continue
				}
				vals := make([]uint64, 0, len(msgs))
				for _, m := range msgs {
					if off+width > len(m.Data) {
						continue
					}
					v, ok := readU(m.Data[off:off+width], endian)
					if !ok {
						continue
					}
					vals = append(vals, v)
				}
				if len(vals) < 3 {
					continue
				}
				ev := scoreCounter(vals, width)
				if len(ev) == 0 {
					continue
				}
				conf := wt.DeriveConfidence(ev)
				if conf.Level == wt.ConfidenceInsufficient || conf.Level == wt.ConfidenceUnknown {
					continue
				}
				hyps = append(hyps, wt.Hypothesis{
					ID:   fmt.Sprintf("ctr_o%d_w%d_%s", off, width, endian),
					Kind: "counter", Offset: off, Length: width,
					Description: fmt.Sprintf("sequence/counter %s%d", endian, width*8),
					Params:      map[string]any{"endian": endian},
					Confidence:  conf, Status: "hypothesis",
				})
			}
		}
	}
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func scoreCounter(vals []uint64, width int) []wt.EvidenceItem {
	mod := uint64(1) << uint(width*8)
	if width >= 8 {
		mod = 0 // no wrap track for 64
	}
	stepsOK := 0
	wraps := 0
	for i := 1; i < len(vals); i++ {
		if vals[i] == vals[i-1]+1 {
			stepsOK++
			continue
		}
		if mod > 0 && vals[i-1] == mod-1 && vals[i] == 0 {
			stepsOK++
			wraps++
			continue
		}
		// allow small gaps of +2/+3 as weak
		if vals[i] > vals[i-1] && vals[i]-vals[i-1] <= 3 {
			stepsOK++
		}
	}
	ratio := float64(stepsOK) / float64(len(vals)-1)
	if ratio < 0.75 {
		return nil
	}
	ev := []wt.EvidenceItem{{
		Kind: "support", Description: "near-unit increments across ordered messages", Weight: 3,
		Metric: "step_ratio", Value: ratio,
	}}
	if wraps > 0 {
		ev = append(ev, wt.EvidenceItem{
			Kind: "support", Description: "observed modular wrap", Weight: 1.5,
			Metric: "wraps", Value: float64(wraps),
		})
	}
	// uniqueness helps
	uniq := map[uint64]struct{}{}
	for _, v := range vals {
		uniq[v] = struct{}{}
	}
	if float64(len(uniq))/float64(len(vals)) > 0.8 {
		ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "high uniqueness", Weight: 1, Metric: "unique_ratio", Value: float64(len(uniq)) / float64(len(vals))})
	}
	return ev
}

// Math helpers exported for compare package
func Pearson(x, y []float64) (float64, bool) {
	if len(x) != len(y) || len(x) < 2 {
		return 0, false
	}
	n := float64(len(x))
	var sx, sy, sxx, syy, sxy float64
	for i := range x {
		sx += x[i]
		sy += y[i]
		sxx += x[i] * x[i]
		syy += y[i] * y[i]
		sxy += x[i] * y[i]
	}
	num := n*sxy - sx*sy
	den := math.Sqrt((n*sxx - sx*sx) * (n*syy - sy*sy))
	if den == 0 {
		return 0, false
	}
	return num / den, true
}

func Spearman(x, y []float64) (float64, bool) {
	if len(x) != len(y) || len(x) < 2 {
		return 0, false
	}
	rx := ranks(x)
	ry := ranks(y)
	return Pearson(rx, ry)
}

func ranks(v []float64) []float64 {
	type pair struct {
		i int
		v float64
	}
	ps := make([]pair, len(v))
	for i, x := range v {
		ps[i] = pair{i, x}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].v < ps[j].v })
	r := make([]float64, len(v))
	for rank, p := range ps {
		r[p.i] = float64(rank + 1)
	}
	return r
}
