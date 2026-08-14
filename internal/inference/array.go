package inference

import (
	"context"
	"fmt"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// ArrayPass detects repeated structures: count field + repeated fixed-width records.
type ArrayPass struct{}

func (ArrayPass) Name() string { return "arrays" }

func (ArrayPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	ds := in.Dataset
	if ds == nil || ds.Len() < 2 {
		return out, nil
	}
	minLen := ds.MinLen()
	if minLen < 4 {
		return out, nil
	}
	var hyps []wt.Hypothesis

	// Stage A: count field at early offsets correlating with (msgLen - header) / elementSize
	countWidths := []int{1, 2}
	if in.Budget != wt.BudgetQuick {
		countWidths = append(countWidths, 4)
	}
	elemSizes := []int{2, 4, 6, 8, 12, 16}
	if in.Budget == wt.BudgetExhaustive {
		elemSizes = []int{2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32}
	}

	maxCountOff := 16
	if in.Budget == wt.BudgetQuick {
		maxCountOff = 8
	}

	for _, cw := range countWidths {
		for countOff := 0; countOff+cw < minLen && countOff < maxCountOff; countOff++ {
			select {
			case <-ctx.Done():
				out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
				return out, ctx.Err()
			default:
			}
			for _, endian := range endiansFor(cw) {
				for _, elem := range elemSizes {
					for _, hdr := range candidateHeaders(countOff, cw, minLen, elem) {
						ev := scoreArrayLayout(ds, countOff, cw, endian, hdr, elem)
						if len(ev) == 0 {
							continue
						}
						conf := wt.DeriveConfidence(ev)
						if conf.Level == wt.ConfidenceInsufficient || conf.Level == wt.ConfidenceUnknown {
							continue
						}
						hyps = append(hyps, wt.Hypothesis{
							ID:   fmt.Sprintf("arr_cnt_o%d_w%d_%s_hdr%d_el%d", countOff, cw, endian, hdr, elem),
							Kind: "array", Offset: hdr, Length: elem, // first element region hint
							Description: fmt.Sprintf("repeated records: count@%d → elemsize=%d header=%d", countOff, elem, hdr),
							Params: map[string]any{
								"count_offset": countOff,
								"count_width":  cw,
								"endian":       endian,
								"header_size":  hdr,
								"element_size": elem,
								"array_offset": hdr,
							},
							Confidence: conf, Status: "hypothesis",
						})
					}
				}
			}
		}
	}

	// Stage B: same-length messages with repeated identical width signatures (no count field)
	if in.Budget != wt.BudgetQuick && ds.MinLen() == ds.MaxLen() {
		hyps = append(hyps, detectRepeatedWidths(ds, in)...)
	}

	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func candidateHeaders(countOff, cw, minLen, elem int) []int {
	cands := []int{countOff + cw}
	// also try a few fixed early headers
	for _, h := range []int{2, 4, 6, 8, 12, 16} {
		if h > countOff+cw && h+elem <= minLen {
			cands = append(cands, h)
		}
	}
	// dedupe
	seen := map[int]bool{}
	var out []int
	for _, h := range cands {
		if h < 0 || seen[h] || h+elem > minLen {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func scoreArrayLayout(ds *wt.Dataset, countOff, cw int, endian string, header, elem int) []wt.EvidenceItem {
	matches := 0
	total := 0
	var counts []int
	for _, m := range ds.Messages {
		if countOff+cw > len(m.Data) || header > len(m.Data) {
			continue
		}
		cntU, ok := readU(m.Data[countOff:countOff+cw], endian)
		if !ok {
			continue
		}
		cnt := int(cntU)
		if cnt < 1 || cnt > 1024 {
			continue
		}
		total++
		need := header + cnt*elem
		if need == len(m.Data) || need+2 == len(m.Data) || need+4 == len(m.Data) { // allow trailer checksum
			matches++
			counts = append(counts, cnt)
		}
	}
	if total < 2 || matches*10 < total*9 { // >= 90%
		return nil
	}
	// require varying counts for stronger evidence (avoid trivial always-1)
	uniq := map[int]struct{}{}
	for _, c := range counts {
		uniq[c] = struct{}{}
	}
	ratio := float64(matches) / float64(total)
	ev := []wt.EvidenceItem{{
		Kind: "support", Description: "count field predicts repeated record span",
		Weight: 4, Metric: "match_ratio", Value: ratio,
	}}
	if len(uniq) >= 2 {
		ev = append(ev, wt.EvidenceItem{
			Kind: "support", Description: "count varies across messages", Weight: 2,
			Metric: "unique_counts", Value: float64(len(uniq)),
		})
	} else {
		ev = append(ev, wt.EvidenceItem{
			Kind: "observation", Description: "count constant — weaker array evidence", Weight: 0.3,
		})
	}
	// soft check: element slices share similar type signature (entropy profile)
	if sigOK := repeatedSignatureOK(ds, header, elem); sigOK {
		ev = append(ev, wt.EvidenceItem{
			Kind: "support", Description: "repeated element byte signatures look similar", Weight: 1.5,
		})
	}
	return ev
}

func repeatedSignatureOK(ds *wt.Dataset, header, elem int) bool {
	if elem < 2 {
		return false
	}
	// Compare byte-wise variance pattern of first vs second element across messages
	agree := 0
	checks := 0
	for _, m := range ds.Messages {
		if header+2*elem > len(m.Data) {
			continue
		}
		a := m.Data[header : header+elem]
		b := m.Data[header+elem : header+2*elem]
		same := 0
		for i := 0; i < elem; i++ {
			// "type signature": treat low-nibble similarity weakly — prefer exact equality rate mid
			if a[i] == b[i] {
				same++
			}
		}
		checks++
		// elements shouldn't be identical always (that would be padding), nor totally random mismatch
		ratio := float64(same) / float64(elem)
		if ratio >= 0.1 && ratio <= 0.9 {
			agree++
		} else if ratio == 1 && elem <= 4 {
			agree++ // small identical structs ok
		}
	}
	return checks >= 1 && agree*2 >= checks
}

func detectRepeatedWidths(ds *wt.Dataset, in *wt.PassInput) []wt.Hypothesis {
	n := ds.MinLen()
	var hyps []wt.Hypothesis
	for _, elem := range []int{4, 8, 16} {
		if n < elem*2 {
			continue
		}
		// find largest header such that (n-header) % elem == 0 and count >= 2
		for hdr := 0; hdr <= 16 && hdr+2*elem <= n; hdr++ {
			if (n-hdr)%elem != 0 {
				continue
			}
			count := (n - hdr) / elem
			if count < 2 || count > 64 {
				continue
			}
			if !repeatedSignatureOK(ds, hdr, elem) {
				continue
			}
			ev := []wt.EvidenceItem{{
				Kind: "support", Description: fmt.Sprintf("fixed layout fits %d×%d-byte records after header %d", count, elem, hdr),
				Weight: 2.5, Metric: "element_count", Value: float64(count),
			}}
			hyps = append(hyps, wt.Hypothesis{
				ID:   fmt.Sprintf("arr_fixed_hdr%d_el%d_n%d", hdr, elem, count),
				Kind: "array", Offset: hdr, Length: elem,
				Description: fmt.Sprintf("fixed repeated records (%d×%d) after offset %d", count, elem, hdr),
				Params: map[string]any{
					"header_size": hdr, "element_size": elem, "count": count, "array_offset": hdr,
				},
				Confidence: wt.DeriveConfidence(ev), Status: "hypothesis",
			})
		}
	}
	return hyps
}
