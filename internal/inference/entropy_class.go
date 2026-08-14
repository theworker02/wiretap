package inference

import (
	"bytes"
	"context"
	"fmt"
	"math"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// EntropyClassPass classifies high-entropy regions as compressed / encrypted-or-compressed /
// random / structured-high-entropy candidates. Never claims "encrypted" without caveats.
type EntropyClassPass struct{}

func (EntropyClassPass) Name() string { return "entropy_class" }

func (EntropyClassPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	ds := in.Dataset
	if ds == nil || ds.Len() == 0 {
		return out, nil
	}

	var hyps []wt.Hypothesis
	for _, m := range ds.Messages {
		select {
		case <-ctx.Done():
			out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
			return out, ctx.Err()
		default:
		}
		if len(m.Data) < 16 {
			continue
		}
		// Classify whole message and high-entropy regions from stats
		label, ev := classifyBytes(m.Data)
		conf := wt.DeriveConfidence(ev)
		if conf.Level == wt.ConfidenceUnknown || conf.Level == wt.ConfidenceInsufficient {
			continue
		}
		hyps = append(hyps, wt.Hypothesis{
			ID: fmt.Sprintf("entropy_%s_%s", m.ID, label), Kind: "entropy",
			Offset: 0, Length: len(m.Data),
			Description: fmt.Sprintf("entropy-class hypothesis: %s", label),
			Params:      map[string]any{"class": label, "message_id": m.ID},
			Confidence:  conf, Status: "hypothesis",
		})
		// Only keep a few message-level classifications
		if len(hyps) >= 8 {
			break
		}
	}

	// Region-level from shared stats: contiguous high entropy
	if len(in.Regions) > 0 {
		for _, r := range in.Regions {
			if r.EntropyMean < 6.5 || r.End-r.Start < 8 {
				continue
			}
			// Sample bytes from first message in region
			m := ds.Messages[0]
			if r.Start >= len(m.Data) {
				continue
			}
			end := r.End
			if end > len(m.Data) {
				end = len(m.Data)
			}
			label, ev := classifyBytes(m.Data[r.Start:end])
			ev = append(ev, wt.EvidenceItem{
				Kind: "observation", Description: fmt.Sprintf("region entropy_mean=%.2f", r.EntropyMean), Weight: 0.5,
			})
			conf := wt.DeriveConfidence(ev)
			if conf.Level == wt.ConfidenceInsufficient || conf.Level == wt.ConfidenceUnknown {
				continue
			}
			hyps = append(hyps, wt.Hypothesis{
				ID: fmt.Sprintf("entropy_reg_%d_%d_%s", r.Start, r.End, label), Kind: "entropy",
				Offset: r.Start, Length: end - r.Start,
				Description: fmt.Sprintf("high-entropy region class hypothesis: %s", label),
				Params:      map[string]any{"class": label},
				Confidence:  conf, Status: "hypothesis",
			})
		}
	}

	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	out.Observations = append(out.Observations, wt.Observation{
		Kind:        "entropy_class",
		Description: "entropy classification uses chi-square, n-gram repeat, and magic headers; encrypted is never asserted without caveats",
	})
	return out, nil
}

func classifyBytes(b []byte) (string, []wt.EvidenceItem) {
	H := shannon(b)
	chi := chiSquareUniform(b)
	rep := bigramRepeat(b)
	magic := detectCompressMagic(b)

	var ev []wt.EvidenceItem
	ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "byte shannon entropy", Weight: 0.5, Metric: "entropy", Value: H})
	ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "chi-square vs uniform", Weight: 0.5, Metric: "chi2", Value: chi})
	ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "bigram repeat rate", Weight: 0.5, Metric: "bigram_repeat", Value: rep})

	if magic != "" {
		ev = append(ev, wt.EvidenceItem{
			Kind: "support", Description: "compression magic header: " + magic, Weight: 4, Metric: "magic", Value: 1,
		})
		return "compressed_candidate", ev
	}

	// Structured high-entropy: high H but significant bigram structure
	if H >= 6.0 && rep >= 0.02 {
		ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "high entropy with repeated n-grams (structured)", Weight: 2})
		return "structured_high_entropy", ev
	}
	if H >= 7.5 && chi < 300 && rep < 0.005 {
		ev = append(ev, wt.EvidenceItem{
			Kind: "support", Description: "near-uniform high entropy — encrypted-or-compressed candidate (not distinguished)", Weight: 2.5,
		})
		ev = append(ev, wt.EvidenceItem{
			Kind: "observation", Description: "Insufficient evidence to claim encryption; could be compressed or CSPRNG", Weight: 0.5,
		})
		return "encrypted_or_compressed_candidate", ev
	}
	if H >= 7.0 && rep < 0.01 {
		ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "high entropy low structure — random-like", Weight: 2})
		return "random_like", ev
	}
	if H >= 5.5 {
		ev = append(ev, wt.EvidenceItem{Kind: "observation", Description: "moderately high entropy without decisive signals", Weight: 1})
		return "high_entropy_unclassified", ev
	}
	return "low_entropy", []wt.EvidenceItem{{Kind: "observation", Description: "low entropy — not a compression/encryption candidate", Weight: 0.2}}
}

func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	n := float64(len(b))
	var H float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		H -= p * math.Log2(p)
	}
	return H
}

func chiSquareUniform(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	exp := float64(len(b)) / 256.0
	var chi float64
	for _, c := range hist {
		d := float64(c) - exp
		chi += d * d / exp
	}
	return chi
}

func bigramRepeat(b []byte) float64 {
	if len(b) < 3 {
		return 0
	}
	seen := map[uint16]int{}
	for i := 0; i+1 < len(b); i++ {
		seen[uint16(b[i])<<8|uint16(b[i+1])]++
	}
	repeats := 0
	for _, c := range seen {
		if c > 1 {
			repeats += c - 1
		}
	}
	return float64(repeats) / float64(len(b)-1)
}

func detectCompressMagic(b []byte) string {
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		return "gzip"
	}
	if len(b) >= 2 && b[0] == 0x78 && (b[1] == 0x01 || b[1] == 0x9c || b[1] == 0xda) {
		return "zlib"
	}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{0x04, 0x22, 0x4d, 0x18}) {
		return "lz4-frame"
	}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte("\x28\xb5\x2f\xfd")) {
		return "zstd"
	}
	return ""
}
