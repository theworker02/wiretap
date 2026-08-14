package inference

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unicode/utf8"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// StringPass detects ASCII/UTF-8/null-terminated/length-prefixed strings.
type StringPass struct{}

func (StringPass) Name() string { return "strings" }

func (StringPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if !in.Config.EnableStrings || in.Dataset == nil || in.Dataset.Len() == 0 {
		return out, nil
	}
	ds := in.Dataset
	maxLen := ds.MaxLen()
	var hyps []wt.Hypothesis

	// Null-terminated / printable runs at consistent offsets
	for off := 0; off < maxLen && off < 256; off++ {
		select {
		case <-ctx.Done():
			out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
			return out, ctx.Err()
		default:
		}
		printable := 0
		total := 0
		nullTerm := 0
		utf8OK := 0
		maxRun := 0
		for _, m := range ds.Messages {
			if off >= len(m.Data) {
				continue
			}
			total++
			run := 0
			for i := off; i < len(m.Data); i++ {
				c := m.Data[i]
				if c == 0 {
					if run >= 3 {
						nullTerm++
					}
					break
				}
				if c >= 32 && c < 127 {
					run++
				} else {
					break
				}
			}
			if run >= 3 {
				printable++
				if run > maxRun {
					maxRun = run
				}
				if utf8.Valid(m.Data[off : off+run]) {
					utf8OK++
				}
			}
		}
		if total < 1 || printable*2 < total || maxRun < 3 {
			continue
		}
		ratio := float64(printable) / float64(total)
		ev := []wt.EvidenceItem{
			{Kind: "support", Description: "printable ASCII run at offset", Weight: 2, Metric: "printable_ratio", Value: ratio},
		}
		kind := "ascii"
		if utf8OK == printable {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "valid UTF-8", Weight: 0.5})
			kind = "utf8"
		}
		if nullTerm*2 >= total {
			ev = append(ev, wt.EvidenceItem{Kind: "support", Description: "null-terminated", Weight: 1.5, Metric: "null_term_ratio", Value: float64(nullTerm) / float64(total)})
			kind = "cstring"
		}
		hyps = append(hyps, wt.Hypothesis{
			ID: fmt.Sprintf("str_o%d_%s", off, kind), Kind: "string", Offset: off, Length: maxRun,
			Description: fmt.Sprintf("%s string candidate (run≈%d)", kind, maxRun),
			Params:      map[string]any{"encoding": kind, "max_run": maxRun},
			Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
		})
	}

	// Length-prefixed strings: u8, u16-le/be, u32-le/be
	type lpSpec struct {
		width  int
		endian string
		name   string
	}
	specs := []lpSpec{{1, "le", "u8"}}
	if in.Budget != wt.BudgetQuick {
		specs = append(specs,
			lpSpec{2, "be", "u16-be"}, lpSpec{2, "le", "u16-le"},
		)
	}
	if in.Budget == wt.BudgetExhaustive {
		specs = append(specs,
			lpSpec{4, "be", "u32-be"}, lpSpec{4, "le", "u32-le"},
		)
	}
	for _, sp := range specs {
		for off := 0; off+sp.width < maxLen && off < 64; off++ {
			select {
			case <-ctx.Done():
				out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
				return out, ctx.Err()
			default:
			}
			matches, total := 0, 0
			for _, m := range ds.Messages {
				if off+sp.width > len(m.Data) {
					continue
				}
				lnU, ok := readU(m.Data[off:off+sp.width], sp.endian)
				if !ok {
					continue
				}
				ln := int(lnU)
				if ln < 3 || ln > 4096 || off+sp.width+ln > len(m.Data) {
					continue
				}
				total++
				chunk := m.Data[off+sp.width : off+sp.width+ln]
				if isPrintable(chunk) {
					matches++
				}
			}
			if total < 2 {
				continue
			}
			ratio := float64(matches) / float64(total)
			if ratio < 0.9 {
				continue
			}
			ev := []wt.EvidenceItem{{
				Kind: "support", Description: fmt.Sprintf("%s length-prefixed printable payload", sp.name),
				Weight: 3, Metric: "match_ratio", Value: ratio,
			}}
			hyps = append(hyps, wt.Hypothesis{
				ID: fmt.Sprintf("str_lp_%s_o%d", sp.name, off), Kind: "string", Offset: off, Length: sp.width,
				Description: fmt.Sprintf("length-prefixed ASCII (%s length)", sp.name),
				Params:      map[string]any{"encoding": "lenpref-" + sp.name, "length_width": sp.width, "endian": sp.endian},
				Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
			})
		}
	}

	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 32 || c >= 127 {
			return false
		}
	}
	return true
}

// BitfieldPass analyzes low-cardinality bytes as flag bitfields.
type BitfieldPass struct{}

func (BitfieldPass) Name() string { return "bitfields" }

func (BitfieldPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if !in.Config.EnableBitfields || len(in.Stats) == 0 {
		return out, nil
	}
	var hyps []wt.Hypothesis
	for _, st := range in.Stats {
		if st.Count < 2 || st.Unique == 0 || st.Unique > 16 {
			continue
		}
		if st.Unique == 1 {
			continue // constant — not a varying bitfield interest for flags
		}
		// Check if values look like flag combinations (subset of bits used)
		usedBits := 0
		var orMask byte
		for v, c := range st.Histogram {
			if c > 0 {
				orMask |= byte(v)
			}
		}
		for i := 0; i < 8; i++ {
			if orMask&(1<<i) != 0 {
				usedBits++
			}
		}
		if usedBits == 0 || usedBits > 6 {
			continue
		}
		// Prefer when unique << 2^usedBits (sparse flag space)
		space := 1 << usedBits
		if st.Unique > space {
			continue
		}
		ev := []wt.EvidenceItem{
			{Kind: "support", Description: "low cardinality byte", Weight: 1.5, Metric: "unique", Value: float64(st.Unique)},
			{Kind: "support", Description: "sparse bit usage", Weight: 1.5, Metric: "used_bits", Value: float64(usedBits)},
			{Kind: "observation", Description: "bit mask of observed values", Weight: 0.5, Metric: "or_mask", Value: float64(orMask)},
		}
		hyps = append(hyps, wt.Hypothesis{
			ID: fmt.Sprintf("bits_o%d", st.Offset), Kind: "bitfield", Offset: st.Offset, Length: 1,
			Description: fmt.Sprintf("flag/bitfield candidate (mask=0x%02x, %d distinct)", orMask, st.Unique),
			Params:      map[string]any{"mask": orMask, "used_bits": usedBits, "unique": st.Unique},
			Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
		})
	}
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

// StructuredPass proposes IPv4/IPv6/MAC/UUID/port pattern candidates (not automatic semantics).
type StructuredPass struct{}

func (StructuredPass) Name() string { return "structured" }

func (StructuredPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if !in.Config.EnableStructured || in.Dataset == nil {
		return out, nil
	}
	ds := in.Dataset
	maxLen := ds.MaxLen()
	var hyps []wt.Hypothesis

	checkPattern := func(off, length int, kind string, valid func([]byte) bool) {
		ok, total := 0, 0
		for _, m := range ds.Messages {
			if off+length > len(m.Data) {
				continue
			}
			total++
			if valid(m.Data[off : off+length]) {
				ok++
			}
		}
		if total < 2 {
			return
		}
		ratio := float64(ok) / float64(total)
		if ratio < 0.9 {
			return
		}
		ev := []wt.EvidenceItem{{
			Kind: "support", Description: fmt.Sprintf("bytes match %s structural pattern (heuristic)", kind),
			Weight: 2, Metric: "match_ratio", Value: ratio,
		}, {
			Kind: "observation", Description: "pattern candidate only — protocol semantics not asserted", Weight: 0.1,
		}}
		if kind == "ipv4" {
			ev = append(ev, wt.EvidenceItem{
				Kind: "observation", Description: "IPv4-shaped bytes ≠ confirmed IP field", Weight: 0.2,
			})
		}
		hyps = append(hyps, wt.Hypothesis{
			ID: fmt.Sprintf("pat_%s_o%d", kind, off), Kind: "pattern", Offset: off, Length: length,
			Description: fmt.Sprintf("%s-shaped byte pattern (heuristic)", kind),
			Params:      map[string]any{"pattern": kind},
			Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
		})
	}

	for off := 0; off+4 <= maxLen && off < 128; off++ {
		checkPattern(off, 4, "ipv4", func(b []byte) bool {
			ip := net.IP(b)
			// Require globally routable-ish heuristic without claiming IP semantics:
			// reject unspecified, loopback-only datasets still allowed as pattern.
			return ip.To4() != nil && !ip.IsUnspecified() && !(b[0] == 0 && b[1] == 0)
		})
		checkPattern(off, 2, "port", func(b []byte) bool {
			p := binary.BigEndian.Uint16(b)
			return p > 0
		})
	}
	for off := 0; off+6 <= maxLen && off < 64; off++ {
		checkPattern(off, 6, "mac", func(b []byte) bool {
			// not all-zero / all-ff
			all0, allF := true, true
			for _, x := range b {
				if x != 0 {
					all0 = false
				}
				if x != 0xff {
					allF = false
				}
			}
			return !all0 && !allF
		})
	}
	for off := 0; off+16 <= maxLen && off < 64; off++ {
		checkPattern(off, 16, "uuid", func(b []byte) bool {
			// RFC 4122 version/variant nibble checks
			ver := (b[6] >> 4) & 0x0f
			if ver < 1 || ver > 5 {
				return false
			}
			variant := (b[8] >> 6) & 0x03
			return variant == 2 // 10xx
		})
		checkPattern(off, 16, "ipv6", func(b []byte) bool {
			ip := net.IP(b)
			return ip.To16() != nil && ip.To4() == nil && !ip.IsUnspecified()
		})
	}

	// Downgrade port-only weak matches: require accompanying evidence from stats
	filtered := hyps[:0]
	for _, h := range hyps {
		if h.Params["pattern"] == "port" {
			if h.Offset >= len(in.Stats) || in.Stats[h.Offset].Unique < 2 {
				continue
			}
			// ports alone are weak — mark low
			h.Confidence.Evidence = append(h.Confidence.Evidence, wt.EvidenceItem{
				Kind: "contradict", Description: "port pattern is weak without session context", Weight: 1,
			})
			h.Confidence = wt.DeriveConfidence(h.Confidence.Evidence)
			if h.Confidence.Level == wt.ConfidenceInsufficient {
				continue
			}
		}
		if h.Params["pattern"] == "mac" {
			h.Confidence.Evidence = append(h.Confidence.Evidence, wt.EvidenceItem{
				Kind: "observation", Description: "MAC pattern is structural only", Weight: 0.2,
			})
		}
		filtered = append(filtered, h)
	}
	out.Hypotheses = prune(filtered, in.Config.MaxCandidates)
	return out, nil
}

// TimestampPass finds plausible unix timestamp fields correlated with capture time.
type TimestampPass struct{}

func (TimestampPass) Name() string { return "timestamps" }

func (TimestampPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if !in.Config.EnableTimestamps || in.Dataset == nil || in.Dataset.Len() < 2 {
		return out, nil
	}
	ds := in.Dataset
	maxLen := ds.MaxLen()
	now := time.Now().Unix()
	minTS := int64(946684800) // 2000-01-01
	maxTS := now + 86400*365  // ~1 year ahead

	var hyps []wt.Hypothesis
	for _, width := range []int{4, 8} {
		for off := 0; off+width <= maxLen && off < 64; off++ {
			for _, endian := range []string{"be", "le"} {
				vals := make([]float64, 0, ds.Len())
				caps := make([]float64, 0, ds.Len())
				plausible := 0
				for _, m := range ds.Messages {
					if off+width > len(m.Data) {
						continue
					}
					u, ok := readU(m.Data[off:off+width], endian)
					if !ok {
						continue
					}
					ts := int64(u)
					if width == 8 && u > 1e12 { // likely millis
						ts = int64(u / 1000)
					}
					if ts >= minTS && ts <= maxTS {
						plausible++
					}
					vals = append(vals, float64(ts))
					if m.Captured != nil {
						caps = append(caps, float64(m.Captured.Unix()))
					}
				}
				if len(vals) < 2 {
					continue
				}
				ratio := float64(plausible) / float64(len(vals))
				if ratio < 0.9 {
					continue
				}
				ev := []wt.EvidenceItem{{
					Kind: "support", Description: "values in plausible unix-time range", Weight: 2,
					Metric: "plausible_ratio", Value: ratio,
				}}
				if len(caps) == len(vals) && len(caps) >= 2 {
					if r, ok := Pearson(vals, caps); ok && r > 0.9 {
						ev = append(ev, wt.EvidenceItem{
							Kind: "support", Description: "correlates with capture timestamps", Weight: 3,
							Metric: "pearson", Value: r,
						})
					} else if ok && r > 0.5 {
						ev = append(ev, wt.EvidenceItem{
							Kind: "support", Description: "weak capture-time correlation", Weight: 1,
							Metric: "pearson", Value: r,
						})
					} else {
						ev = append(ev, wt.EvidenceItem{
							Kind: "contradict", Description: "no capture-time correlation", Weight: 1,
						})
					}
				} else {
					ev = append(ev, wt.EvidenceItem{
						Kind: "observation", Description: "no capture timestamps available for correlation", Weight: 0.2,
					})
					// Without capture correlation, require strong monotonicity
					inc := 0
					for i := 1; i < len(vals); i++ {
						if vals[i] >= vals[i-1] {
							inc++
						}
					}
					if float64(inc)/float64(len(vals)-1) < 0.8 {
						continue // do not label arbitrary ints as timestamps
					}
					ev = append(ev, wt.EvidenceItem{
						Kind: "support", Description: "monotonic non-decreasing values", Weight: 1.5,
					})
				}
				conf := wt.DeriveConfidence(ev)
				if conf.Level == wt.ConfidenceInsufficient || conf.Level == wt.ConfidenceUnknown {
					continue
				}
				hyps = append(hyps, wt.Hypothesis{
					ID:   fmt.Sprintf("ts_o%d_w%d_%s", off, width, endian),
					Kind: "timestamp", Offset: off, Length: width,
					Description: fmt.Sprintf("unix timestamp candidate (%s%d)", endian, width*8),
					Params:      map[string]any{"endian": endian, "unit": "seconds"},
					Confidence:  conf, Status: "hypothesis",
				})
			}
		}
	}
	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}
