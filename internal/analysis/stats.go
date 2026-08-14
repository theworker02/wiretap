package analysis

import (
	"math"
	"sort"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// ByteStats is an alias for the public per-offset stats type.
type ByteStats = wt.ByteStat

// Region is an alias for the public region type.
type Region = wt.Region

// ComputeByteStats computes per-offset stats for offsets 0..maxLen-1.
func ComputeByteStats(ds *wt.Dataset) []ByteStats {
	if ds == nil || ds.Len() == 0 {
		return nil
	}
	maxLen := ds.MaxLen()
	stats := make([]ByteStats, maxLen)
	values := make([][]byte, maxLen)
	for _, m := range ds.Messages {
		for i, b := range m.Data {
			values[i] = append(values[i], b)
		}
	}
	for off := 0; off < maxLen; off++ {
		vals := values[off]
		st := ByteStats{Offset: off, Count: len(vals)}
		if len(vals) == 0 {
			stats[off] = st
			continue
		}
		var sum float64
		minB, maxB := vals[0], vals[0]
		for _, b := range vals {
			st.Histogram[b]++
			sum += float64(b)
			if b < minB {
				minB = b
			}
			if b > maxB {
				maxB = b
			}
		}
		st.Min, st.Max = minB, maxB
		st.Mean = sum / float64(len(vals))
		unique := 0
		mode, modeCount := byte(0), 0
		var ent float64
		n := float64(len(vals))
		for v, c := range st.Histogram {
			if c == 0 {
				continue
			}
			unique++
			if c > modeCount {
				modeCount = c
				mode = byte(v)
			}
			p := float64(c) / n
			ent -= p * math.Log2(p)
		}
		st.Unique = unique
		st.Mode = mode
		st.ModeCount = modeCount
		st.Entropy = ent
		st.ConstantProbability = float64(modeCount) / n

		sorted := append([]byte(nil), vals...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		if len(sorted)%2 == 1 {
			st.Median = float64(sorted[len(sorted)/2])
		} else {
			st.Median = (float64(sorted[len(sorted)/2-1]) + float64(sorted[len(sorted)/2])) / 2
		}
		var varSum float64
		for _, b := range vals {
			d := float64(b) - st.Mean
			varSum += d * d
		}
		st.Variance = varSum / n
		st.StdDev = math.Sqrt(st.Variance)

		msgs := append([]*wt.Message(nil), ds.Messages...)
		sort.Slice(msgs, func(i, j int) bool { return msgs[i].ID < msgs[j].ID })
		changes, pairs := 0, 0
		var prev *byte
		for _, m := range msgs {
			if off >= len(m.Data) {
				continue
			}
			b := m.Data[off]
			if prev != nil {
				pairs++
				if b != *prev {
					changes++
				}
			}
			bb := b
			prev = &bb
		}
		if pairs > 0 {
			st.ChangeFrequency = float64(changes) / float64(pairs)
		}
		stats[off] = st
	}
	return stats
}

// GroupEntropyRegions clusters consecutive offsets by entropy bands.
func GroupEntropyRegions(stats []ByteStats) []Region {
	if len(stats) == 0 {
		return nil
	}
	band := func(e float64) string {
		switch {
		case e < 0.5:
			return "constant"
		case e < 2.0:
			return "low_entropy"
		case e > 6.0:
			return "high_entropy"
		default:
			return "mixed"
		}
	}
	var regions []Region
	start := 0
	cur := band(stats[0].Entropy)
	sumEnt := stats[0].Entropy
	count := 1
	flush := func(end int) {
		mean := sumEnt / float64(count)
		r := Region{
			Start:       start,
			End:         end,
			Kind:        cur,
			EntropyMean: mean,
			Metrics:     map[string]float64{"entropy_mean": mean},
		}
		ev := []wt.EvidenceItem{{
			Kind: "observation", Description: "entropy band grouping", Weight: 1,
			Metric: "entropy_mean", Value: mean,
		}}
		if cur == "constant" {
			allConst := true
			var val byte
			for i := start; i < end; i++ {
				if stats[i].Unique != 1 {
					allConst = false
					break
				}
				if i == start {
					val = stats[i].Mode
				} else if stats[i].Mode != val {
					allConst = false
					break
				}
			}
			if allConst {
				r.Kind = "constant"
				v := val
				r.Value = &v
				ev = append(ev, wt.EvidenceItem{
					Kind: "support", Description: "unique==1 across region", Weight: 2,
				})
			}
		}
		r.Confidence = wt.DeriveConfidence(ev)
		regions = append(regions, r)
	}
	for i := 1; i < len(stats); i++ {
		b := band(stats[i].Entropy)
		if b != cur {
			flush(i)
			start = i
			cur = b
			sumEnt = stats[i].Entropy
			count = 1
		} else {
			sumEnt += stats[i].Entropy
			count++
		}
	}
	flush(len(stats))
	return regions
}

// DetectConstants finds offsets/regions that are constant across all messages covering them.
func DetectConstants(stats []ByteStats) []Region {
	var out []Region
	i := 0
	for i < len(stats) {
		if stats[i].Count == 0 || stats[i].Unique != 1 {
			i++
			continue
		}
		start := i
		val := stats[i].Mode
		for i < len(stats) && stats[i].Count > 0 && stats[i].Unique == 1 && stats[i].Mode == val {
			i++
		}
		v := val
		ev := []wt.EvidenceItem{
			{Kind: "support", Description: "identical byte across all covering messages", Weight: 3, Metric: "unique", Value: 1},
			{Kind: "observation", Description: "constant probability", Weight: 1, Metric: "constant_probability", Value: stats[start].ConstantProbability},
		}
		out = append(out, Region{
			Start: start, End: i, Kind: "constant", Value: &v,
			EntropyMean: 0,
			Confidence:  wt.DeriveConfidence(ev),
			Metrics:     map[string]float64{"value": float64(v)},
		})
	}
	return out
}

// DetectChangedRegions finds offsets that differ between two message sets (A vs B).
func DetectChangedRegions(a, b []*wt.Message) []Region {
	maxLen := 0
	for _, m := range a {
		if len(m.Data) > maxLen {
			maxLen = len(m.Data)
		}
	}
	for _, m := range b {
		if len(m.Data) > maxLen {
			maxLen = len(m.Data)
		}
	}
	diff := make([]bool, maxLen)
	for off := 0; off < maxLen; off++ {
		setA := map[byte]struct{}{}
		setB := map[byte]struct{}{}
		for _, m := range a {
			if off < len(m.Data) {
				setA[m.Data[off]] = struct{}{}
			}
		}
		for _, m := range b {
			if off < len(m.Data) {
				setB[m.Data[off]] = struct{}{}
			}
		}
		same := true
		if len(setA) != len(setB) {
			same = false
		} else {
			for k := range setA {
				if _, ok := setB[k]; !ok {
					same = false
					break
				}
			}
		}
		if !same {
			diff[off] = true
		}
		if !diff[off] && len(a) > 0 && len(b) > 0 {
			if len(setA) == 1 && len(setB) == 1 {
				var va, vb byte
				for k := range setA {
					va = k
				}
				for k := range setB {
					vb = k
				}
				if va != vb {
					diff[off] = true
				}
			}
		}
	}
	var regions []Region
	i := 0
	for i < maxLen {
		if !diff[i] {
			i++
			continue
		}
		start := i
		for i < maxLen && diff[i] {
			i++
		}
		ev := []wt.EvidenceItem{{
			Kind: "observation", Description: "byte value sets differ between cohorts", Weight: 2,
		}}
		regions = append(regions, Region{
			Start: start, End: i, Kind: "changed",
			Confidence: wt.DeriveConfidence(ev),
		})
	}
	return regions
}
