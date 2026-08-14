package inference

import (
	"fmt"
	"sort"
	"strings"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// CompeteHypotheses prunes near-duplicates and ranks clearer winners per offset span.
// Losers are recorded on winners' Alternates with a short reason in Params["lost_to_reason"].
// topN caps retained hypotheses (0 = keep all winners after collapse).
//
// Prefer fewer high-quality hypotheses: same-span Medium losers under a High winner are
// dropped, weak Medium integer/pattern spam overlapping High structural winners is pruned,
// nested envelopes lose to concrete structure, and overlapping same-family fields collapse
// to non-overlapping winners (improves measured precision / lowers FPR without inventing confidence).
func CompeteHypotheses(hyps []wt.Hypothesis, topN int) []wt.Hypothesis {
	if len(hyps) == 0 {
		return hyps
	}
	// Collapse near-duplicates first (same kind+offset+length, or identical ID prefix families).
	hyps = collapseNearDuplicates(hyps)

	type spanKey struct {
		off, length int
	}
	groups := map[spanKey][]int{}
	for i, h := range hyps {
		if h.Offset < 0 {
			continue
		}
		k := spanKey{h.Offset, h.Length}
		groups[k] = append(groups[k], i)
	}

	keep := make([]bool, len(hyps))
	for i := range hyps {
		keep[i] = true
	}
	for _, idxs := range groups {
		if len(idxs) < 2 {
			continue
		}
		sort.SliceStable(idxs, func(a, b int) bool {
			ia, ib := idxs[a], idxs[b]
			// Prefer High over Medium when scores are close.
			la, lb := confRank(hyps[ia]), confRank(hyps[ib])
			if la != lb {
				return la > lb
			}
			if hyps[ia].Confidence.Score == hyps[ib].Confidence.Score {
				if kindRank(hyps[ia].Kind) == kindRank(hyps[ib].Kind) {
					return hyps[ia].ID < hyps[ib].ID
				}
				return kindRank(hyps[ia].Kind) > kindRank(hyps[ib].Kind)
			}
			return hyps[ia].Confidence.Score > hyps[ib].Confidence.Score
		})
		winner := idxs[0]
		var alts []string
		for _, i := range idxs[1:] {
			reason := loseReason(hyps[winner], hyps[i])
			alts = append(alts, hyps[i].ID)
			if hyps[i].Params == nil {
				hyps[i].Params = map[string]any{}
			}
			hyps[i].Params["lost_to"] = hyps[winner].ID
			hyps[i].Params["lost_to_reason"] = reason
			// Drop clearly dominated same-span losers.
			// Keep only High (or near-score) distinct-kind alternates — Medium spam under a
			// High/strong winner is not retained as a primary hypothesis.
			drop := hyps[i].Kind == hyps[winner].Kind ||
				hyps[i].Confidence.Score+0.12 < hyps[winner].Confidence.Score ||
				(confRank(hyps[winner]) > confRank(hyps[i]) && hyps[i].Confidence.Level != wt.ConfidenceHigh)
			if drop {
				keep[i] = false
			}
		}
		hyps[winner].Alternates = uniqueStrings(append(hyps[winner].Alternates, alts...))
		if hyps[winner].Params == nil {
			hyps[winner].Params = map[string]any{}
		}
		hyps[winner].Params["competition_rank"] = 1
		hyps[winner].Params["competition_pool"] = len(idxs)
	}

	// Drop nested envelopes before weak-overlap pruning so they cannot suppress
	// Medium field hypotheses that are still useful for recall matching.
	pruneNestedUnderStructure(hyps, keep)
	pruneWeakOverlaps(hyps, keep)
	pruneContainedFamily(hyps, keep)
	pruneOverlappingFamily(hyps, keep)
	pruneCounterUnderString(hyps, keep)

	out := make([]wt.Hypothesis, 0, len(hyps))
	for i, h := range hyps {
		if keep[i] {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := confRank(out[i]), confRank(out[j])
		if ri != rj {
			return ri > rj
		}
		if out[i].Confidence.Score == out[j].Confidence.Score {
			if out[i].Offset == out[j].Offset {
				return out[i].ID < out[j].ID
			}
			return out[i].Offset < out[j].Offset
		}
		return out[i].Confidence.Score > out[j].Confidence.Score
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

func confRank(h wt.Hypothesis) int {
	switch h.Confidence.Level {
	case wt.ConfidenceHigh:
		return 4
	case wt.ConfidenceMedium:
		return 3
	case wt.ConfidenceLow:
		return 2
	default:
		return 1
	}
}

// pruneWeakOverlaps drops Low/weak-Medium speculative kinds that overlap a High
// structural winner (checksum/length/array/counter/typefield/string/timestamp).
func pruneWeakOverlaps(hyps []wt.Hypothesis, keep []bool) {
	var structural []int
	for i, h := range hyps {
		if !keep[i] || h.Offset < 0 {
			continue
		}
		if h.Confidence.Level != wt.ConfidenceHigh {
			continue
		}
		if !structuralKind(h.Kind) {
			continue
		}
		structural = append(structural, i)
	}
	for i, h := range hyps {
		if !keep[i] || h.Offset < 0 {
			continue
		}
		if !speculativeKind(h.Kind) {
			continue
		}
		// Keep High speculative only; Medium/Low speculative overlapping structure goes.
		if h.Confidence.Level == wt.ConfidenceHigh {
			continue
		}
		if h.Confidence.Level == wt.ConfidenceMedium && h.Confidence.Score >= 0.85 && structuralKind(h.Kind) {
			continue
		}
		he := h.Offset + h.Length
		for _, si := range structural {
			w := hyps[si]
			we := w.Offset + w.Length
			if h.Offset < we && w.Offset < he {
				keep[i] = false
				markLost(&hyps[i], w.ID, fmt.Sprintf("weak %s under High structural %s", h.Kind, w.Kind))
				break
			}
		}
	}
}

// pruneNestedUnderStructure drops nested envelope hypotheses when concrete High/strong
// structural fields already cover the protocol (nested is explanatory, not a boundary claim).
func pruneNestedUnderStructure(hyps []wt.Hypothesis, keep []bool) {
	hasConcrete := false
	for i, h := range hyps {
		if !keep[i] {
			continue
		}
		if h.Confidence.Level != wt.ConfidenceHigh && !(h.Confidence.Level == wt.ConfidenceMedium && h.Confidence.Score >= 0.8) {
			continue
		}
		switch h.Kind {
		case "length", "checksum", "counter", "array", "typefield", "string", "timestamp":
			hasConcrete = true
		}
	}
	if !hasConcrete {
		return
	}
	for i, h := range hyps {
		if !keep[i] || h.Kind != "nested" {
			continue
		}
		keep[i] = false
		markLost(&hyps[i], "", "nested envelope superseded by concrete structural hypotheses")
	}
}

// pruneContainedFamily drops counters/lengths/strings fully contained in a stronger
// same-family or dominating structural field (e.g. 1-byte counter inside a 2-byte counter,
// or counter bytes inside a High timestamp).
func pruneContainedFamily(hyps []wt.Hypothesis, keep []bool) {
	type idxHyp struct {
		i int
		h wt.Hypothesis
	}
	var cands []idxHyp
	for i, h := range hyps {
		if !keep[i] || h.Offset < 0 || h.Length <= 0 {
			continue
		}
		if confRank(h) < 3 {
			continue
		}
		cands = append(cands, idxHyp{i, h})
	}
	for _, a := range cands {
		if !keep[a.i] {
			continue
		}
		ae := a.h.Offset + a.h.Length
		for _, b := range cands {
			if a.i == b.i || !keep[b.i] {
				continue
			}
			be := b.h.Offset + b.h.Length
			// a fully inside b
			if !(a.h.Offset >= b.h.Offset && ae <= be && (a.h.Offset > b.h.Offset || ae < be)) {
				continue
			}
			drop := false
			reason := ""
			switch {
			case a.h.Kind == "counter" && (b.h.Kind == "counter" || b.h.Kind == "timestamp" || b.h.Kind == "length"):
				if confRank(b.h) > confRank(a.h) || b.h.Confidence.Score >= a.h.Confidence.Score-0.05 {
					drop = true
					reason = fmt.Sprintf("contained %s under %s %s", a.h.Kind, b.h.Kind, b.h.ID)
				}
			case a.h.Kind == "length" && b.h.Kind == "length":
				if b.h.Length >= a.h.Length && (confRank(b.h) > confRank(a.h) || b.h.Confidence.Score >= a.h.Confidence.Score) {
					drop = true
					reason = fmt.Sprintf("contained length under %s", b.h.ID)
				}
			case a.h.Kind == "string" && b.h.Kind == "string":
				if b.h.Length > a.h.Length || (b.h.Length == a.h.Length && b.h.ID < a.h.ID) {
					drop = true
					reason = fmt.Sprintf("contained string under %s", b.h.ID)
				}
			case a.h.Kind == "counter" && b.h.Kind == "string" && confRank(b.h) >= 3 && b.h.Length >= 2:
				drop = true
				reason = fmt.Sprintf("counter inside string %s", b.h.ID)
			}
			if drop {
				keep[a.i] = false
				markLost(&hyps[a.i], b.h.ID, reason)
				break
			}
		}
	}
}

// pruneOverlappingFamily greedily keeps non-overlapping winners within length/counter/string
// families so shifted aliases (len@4 vs len@5) do not all count as precision-eligible FPs.
func pruneOverlappingFamily(hyps []wt.Hypothesis, keep []bool) {
	families := []string{"length", "counter", "string", "timestamp"}
	for _, fam := range families {
		var idxs []int
		for i, h := range hyps {
			if !keep[i] || h.Offset < 0 || h.Length <= 0 {
				continue
			}
			if h.Kind != fam {
				continue
			}
			if confRank(h) < 3 {
				continue
			}
			idxs = append(idxs, i)
		}
		if len(idxs) < 2 {
			continue
		}
		sort.SliceStable(idxs, func(a, b int) bool {
			ia, ib := idxs[a], idxs[b]
			ra, rb := confRank(hyps[ia]), confRank(hyps[ib])
			if ra != rb {
				return ra > rb
			}
			if hyps[ia].Confidence.Score != hyps[ib].Confidence.Score {
				return hyps[ia].Confidence.Score > hyps[ib].Confidence.Score
			}
			// Prefer wider fields, then earlier offset, then stable ID.
			if hyps[ia].Length != hyps[ib].Length {
				return hyps[ia].Length > hyps[ib].Length
			}
			if hyps[ia].Offset != hyps[ib].Offset {
				return hyps[ia].Offset < hyps[ib].Offset
			}
			return hyps[ia].ID < hyps[ib].ID
		})
		type accepted struct{ s, e int }
		var taken []accepted
		for _, i := range idxs {
			if !keep[i] {
				continue
			}
			s, e := hyps[i].Offset, hyps[i].Offset+hyps[i].Length
			conflict := false
			var loserTo string
			for _, t := range taken {
				if overlapsHeavy(s, e, t.s, t.e) {
					conflict = true
					loserTo = fmt.Sprintf("%s@%d", fam, t.s)
					break
				}
			}
			if conflict {
				keep[i] = false
				markLost(&hyps[i], loserTo, fmt.Sprintf("overlapping %s collapsed to non-overlapping winners", fam))
				continue
			}
			taken = append(taken, accepted{s, e})
		}
	}
}

// overlapsHeavy reports ≥50% overlap of the smaller span.
func overlapsHeavy(a0, a1, b0, b1 int) bool {
	lo := a0
	if b0 > lo {
		lo = b0
	}
	hi := a1
	if b1 < hi {
		hi = b1
	}
	if hi <= lo {
		return false
	}
	overlap := hi - lo
	lena, lenb := a1-a0, b1-b0
	smaller := lena
	if lenb < smaller {
		smaller = lenb
	}
	if smaller <= 0 {
		return false
	}
	return overlap*2 >= smaller // half or more of the smaller span
}

// pruneCounterUnderString drops counters that heavily overlap a kept string field
// (common FP: integer-looking payload bytes inside UTF-8 / length-prefixed strings).
func pruneCounterUnderString(hyps []wt.Hypothesis, keep []bool) {
	var strings []int
	for i, h := range hyps {
		if !keep[i] || h.Kind != "string" || h.Offset < 0 {
			continue
		}
		if confRank(h) < 3 {
			continue
		}
		strings = append(strings, i)
	}
	if len(strings) == 0 {
		return
	}
	for i, h := range hyps {
		if !keep[i] || h.Kind != "counter" || h.Offset < 0 {
			continue
		}
		he := h.Offset + h.Length
		for _, si := range strings {
			s := hyps[si]
			se := s.Offset + s.Length
			if overlapsHeavy(h.Offset, he, s.Offset, se) {
				keep[i] = false
				markLost(&hyps[i], s.ID, "counter overlaps string field")
				break
			}
		}
	}
}

func markLost(h *wt.Hypothesis, winnerID, reason string) {
	if h.Params == nil {
		h.Params = map[string]any{}
	}
	if winnerID != "" {
		h.Params["lost_to"] = winnerID
	}
	h.Params["lost_to_reason"] = reason
}

func structuralKind(kind string) bool {
	switch kind {
	case "checksum", "length", "array", "counter", "typefield", "string", "timestamp":
		return true
	default:
		// nested is an envelope hypothesis — not a concrete boundary claim
		return false
	}
}

func speculativeKind(kind string) bool {
	switch kind {
	case "integer", "pattern", "varint", "protobuf_like", "bitfield", "entropy":
		return true
	default:
		return false
	}
}

func collapseNearDuplicates(hyps []wt.Hypothesis) []wt.Hypothesis {
	type key struct {
		kind        string
		off, length int
		sig         string
	}
	best := map[key]wt.Hypothesis{}
	order := []key{}
	for _, h := range hyps {
		sig := paramSig(h)
		k := key{h.Kind, h.Offset, h.Length, sig}
		if prev, ok := best[k]; ok {
			if confRank(h) > confRank(prev) ||
				(confRank(h) == confRank(prev) && h.Confidence.Score > prev.Confidence.Score) ||
				(confRank(h) == confRank(prev) && h.Confidence.Score == prev.Confidence.Score && h.ID < prev.ID) {
				best[k] = h
			}
			continue
		}
		best[k] = h
		order = append(order, k)
	}
	out := make([]wt.Hypothesis, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

func paramSig(h wt.Hypothesis) string {
	if h.Params == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	for _, k := range []string{"endian", "mode", "signed", "algorithm", "encoding", "width"} {
		if v, ok := h.Params[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, ",")
}

func kindRank(kind string) int {
	switch kind {
	case "checksum", "length", "array", "counter", "typefield":
		return 5
	case "string", "timestamp", "bitfield", "tlv":
		return 4
	case "integer":
		return 3
	case "pattern", "entropy", "varint", "protobuf_like":
		return 2
	default:
		return 1
	}
}

func loseReason(winner, loser wt.Hypothesis) string {
	if winner.Kind != loser.Kind {
		return fmt.Sprintf("lower priority kind %s vs winner %s (score %.2f < %.2f)",
			loser.Kind, winner.Kind, loser.Confidence.Score, winner.Confidence.Score)
	}
	if loser.Confidence.Score < winner.Confidence.Score {
		return fmt.Sprintf("lower confidence score %.2f vs %.2f", loser.Confidence.Score, winner.Confidence.Score)
	}
	return fmt.Sprintf("tied score; stable id order prefers %s", winner.ID)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ExplainCompetition returns top-N hypotheses overlapping [start,end) with loser notes.
func ExplainCompetition(hyps []wt.Hypothesis, start, end, topN int) []wt.Hypothesis {
	var hit []wt.Hypothesis
	for _, h := range hyps {
		if h.Offset < 0 {
			continue
		}
		he := h.Offset + h.Length
		if h.Offset < end && start < he {
			hit = append(hit, h)
		}
	}
	sort.SliceStable(hit, func(i, j int) bool {
		if confRank(hit[i]) != confRank(hit[j]) {
			return confRank(hit[i]) > confRank(hit[j])
		}
		if hit[i].Confidence.Score == hit[j].Confidence.Score {
			return hit[i].ID < hit[j].ID
		}
		return hit[i].Confidence.Score > hit[j].Confidence.Score
	})
	if topN > 0 && len(hit) > topN {
		hit = hit[:topN]
	}
	return hit
}
