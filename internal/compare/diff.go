package compare

import (
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/theworker02/wiretap/internal/analysis"
	"github.com/theworker02/wiretap/internal/inference"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// DiffResult holds differential comparison output.
type DiffResult struct {
	LabelKey     string        `json:"label_key"`
	CohortA      string        `json:"cohort_a"`
	CohortB      string        `json:"cohort_b"`
	CountA       int           `json:"count_a"`
	CountB       int           `json:"count_b"`
	Changed      []wt.Region   `json:"changed_regions"`
	Correlations []Correlation `json:"correlations,omitempty"`
}

// Correlation links a numeric label to byte offsets / integer fields.
type Correlation struct {
	Offset      int           `json:"offset"`
	Length      int           `json:"length"`
	Method      string        `json:"method"` // pearson|spearman|exact|monotonic|transform
	Coefficient float64       `json:"coefficient,omitempty"`
	Transform   string        `json:"transform,omitempty"`
	Confidence  wt.Confidence `json:"confidence"`
	Description string        `json:"description"`
}

// Diff compares two label cohorts and optionally correlates a numeric label.
func Diff(ds *wt.Dataset, labelKey, valueA, valueB string) (*DiffResult, error) {
	if ds == nil || ds.Len() == 0 {
		return nil, wt.ErrEmptyDataset
	}
	if labelKey == "" {
		return nil, fmt.Errorf("%w: label key required", wt.ErrInvalidLabel)
	}
	a := ds.FilterByLabel(labelKey, valueA)
	b := ds.FilterByLabel(labelKey, valueB)
	if len(a) == 0 || len(b) == 0 {
		return nil, fmt.Errorf("%w: need messages for both %s=%s and %s=%s (got %d and %d)",
			wt.ErrInvalidLabel, labelKey, valueA, labelKey, valueB, len(a), len(b))
	}
	changed := analysis.DetectChangedRegions(a, b)
	pub := make([]wt.Region, len(changed))
	for i, r := range changed {
		pub[i] = wt.Region{
			Start: r.Start, End: r.End, Kind: r.Kind, EntropyMean: r.EntropyMean,
			Value: r.Value, Confidence: r.Confidence, Metrics: r.Metrics,
		}
	}
	return &DiffResult{
		LabelKey: labelKey,
		CohortA:  valueA,
		CohortB:  valueB,
		CountA:   len(a),
		CountB:   len(b),
		Changed:  pub,
	}, nil
}

// CorrelateNumeric correlates label values (parsed as float) with integer field candidates.
func CorrelateNumeric(ds *wt.Dataset, labelKey string, maxOffset int) ([]Correlation, error) {
	if ds == nil || ds.Len() < 3 {
		return nil, wt.ErrInsufficientEv
	}
	type pair struct {
		label float64
		msg   *wt.Message
	}
	var pairs []pair
	for _, m := range ds.Messages {
		raw, ok := m.Labels[labelKey]
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		pairs = append(pairs, pair{v, m})
	}
	if len(pairs) < 3 {
		return nil, fmt.Errorf("%w: need ≥3 numeric labels for %q", wt.ErrInsufficientEv, labelKey)
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].msg.ID < pairs[j].msg.ID })

	labels := make([]float64, len(pairs))
	for i, p := range pairs {
		labels[i] = p.label
	}

	maxLen := 0
	for _, p := range pairs {
		if len(p.msg.Data) > maxLen {
			maxLen = len(p.msg.Data)
		}
	}
	if maxOffset <= 0 || maxOffset > maxLen {
		maxOffset = maxLen
	}

	var out []Correlation
	for _, width := range []int{1, 2, 4} {
		for off := 0; off+width <= maxOffset && off < 256; off++ {
			for _, endian := range []string{"be", "le"} {
				if width == 1 && endian == "be" {
					continue
				}
				vals := make([]float64, 0, len(pairs))
				okAll := true
				for _, p := range pairs {
					if off+width > len(p.msg.Data) {
						okAll = false
						break
					}
					u, ok := readU(p.msg.Data[off:off+width], endian)
					if !ok {
						okAll = false
						break
					}
					vals = append(vals, float64(u))
				}
				if !okAll || len(vals) != len(labels) {
					continue
				}

				// exact match
				exact := true
				for i := range vals {
					if vals[i] != labels[i] {
						exact = false
						break
					}
				}
				if exact {
					ev := []wt.EvidenceItem{{Kind: "support", Description: "exact equality with label", Weight: 5}}
					out = append(out, Correlation{
						Offset: off, Length: width, Method: "exact", Coefficient: 1,
						Description: fmt.Sprintf("field [%d:%d] %s exactly equals label %s", off, off+width, endian, labelKey),
						Confidence:  wt.DeriveConfidence(ev),
					})
					continue
				}

				if r, ok := inference.Pearson(vals, labels); ok && math.Abs(r) >= 0.95 {
					ev := []wt.EvidenceItem{{Kind: "support", Description: "Pearson correlation", Weight: 3, Metric: "pearson", Value: r}}
					out = append(out, Correlation{
						Offset: off, Length: width, Method: "pearson", Coefficient: r,
						Description: fmt.Sprintf("Pearson r=%.4f for [%d:%d] %s vs %s", r, off, off+width, endian, labelKey),
						Confidence:  wt.DeriveConfidence(ev),
					})
				}
				if r, ok := inference.Spearman(vals, labels); ok && math.Abs(r) >= 0.95 {
					ev := []wt.EvidenceItem{{Kind: "support", Description: "Spearman correlation", Weight: 3, Metric: "spearman", Value: r}}
					out = append(out, Correlation{
						Offset: off, Length: width, Method: "spearman", Coefficient: r,
						Description: fmt.Sprintf("Spearman ρ=%.4f for [%d:%d] %s vs %s", r, off, off+width, endian, labelKey),
						Confidence:  wt.DeriveConfidence(ev),
					})
				}

				// monotonic co-movement
				if monoAgree(vals, labels) > 0.9 {
					ev := []wt.EvidenceItem{{Kind: "support", Description: "monotonic agreement with label", Weight: 2}}
					out = append(out, Correlation{
						Offset: off, Length: width, Method: "monotonic",
						Description: fmt.Sprintf("monotonic agreement [%d:%d] %s vs %s", off, off+width, endian, labelKey),
						Confidence:  wt.DeriveConfidence(ev),
					})
				}

				// bounded transform search: value*C, value+C, value*C+D
				if t, ok := findTransform(vals, labels); ok {
					ev := []wt.EvidenceItem{{Kind: "support", Description: "affine transform match " + t, Weight: 4}}
					out = append(out, Correlation{
						Offset: off, Length: width, Method: "transform", Transform: t,
						Description: fmt.Sprintf("transform %s maps field [%d:%d] to %s", t, off, off+width, labelKey),
						Confidence:  wt.DeriveConfidence(ev),
					})
				}
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Confidence.Score > out[j].Confidence.Score
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out, nil
}

func readU(b []byte, endian string) (uint64, bool) {
	switch len(b) {
	case 1:
		return uint64(b[0]), true
	case 2:
		if endian == "le" {
			return uint64(uint16(b[0]) | uint16(b[1])<<8), true
		}
		return uint64(uint16(b[1]) | uint16(b[0])<<8), true
	case 4:
		if endian == "le" {
			return uint64(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24), true
		}
		return uint64(uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24), true
	default:
		return 0, false
	}
}

func monoAgree(x, y []float64) float64 {
	if len(x) < 2 {
		return 0
	}
	ok := 0
	for i := 1; i < len(x); i++ {
		dx := x[i] - x[i-1]
		dy := y[i] - y[i-1]
		if dx == 0 && dy == 0 {
			ok++
			continue
		}
		if (dx > 0 && dy > 0) || (dx < 0 && dy < 0) {
			ok++
		}
	}
	return float64(ok) / float64(len(x)-1)
}

func findTransform(vals, labels []float64) (string, bool) {
	// value + C
	c0 := labels[0] - vals[0]
	ok := true
	for i := range vals {
		if math.Abs((vals[i]+c0)-labels[i]) > 1e-6 {
			ok = false
			break
		}
	}
	if ok {
		return fmt.Sprintf("value%+g", c0), true
	}
	// value * C
	if vals[0] != 0 {
		c1 := labels[0] / vals[0]
		ok = true
		for i := range vals {
			if math.Abs(vals[i]*c1-labels[i]) > 1e-6 {
				ok = false
				break
			}
		}
		if ok {
			return fmt.Sprintf("value*%g", c1), true
		}
	}
	// value * C + D using first two points
	if len(vals) >= 2 && vals[1] != vals[0] {
		c := (labels[1] - labels[0]) / (vals[1] - vals[0])
		d := labels[0] - c*vals[0]
		ok = true
		for i := range vals {
			if math.Abs(c*vals[i]+d-labels[i]) > 1e-6 {
				ok = false
				break
			}
		}
		if ok {
			return fmt.Sprintf("value*%g%+g", c, d), true
		}
	}
	return "", false
}
