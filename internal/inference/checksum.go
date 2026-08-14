package inference

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// ChecksumAlg identifies a tested algorithm.
type ChecksumAlg string

const (
	AlgXOR8       ChecksumAlg = "xor8"
	AlgSUM8       ChecksumAlg = "sum8"
	AlgSUM16      ChecksumAlg = "sum16"
	AlgSUM32      ChecksumAlg = "sum32"
	AlgFletcher16 ChecksumAlg = "fletcher16"
	AlgFletcher32 ChecksumAlg = "fletcher32"
	AlgAdler32    ChecksumAlg = "adler32"
	AlgCRC8       ChecksumAlg = "crc8"
	AlgCRC16IBM   ChecksumAlg = "crc16-ibm"
	AlgCRC16CCITT ChecksumAlg = "crc16-ccitt"
	AlgCRC32IEEE  ChecksumAlg = "crc32-ieee"
	AlgCRC32C     ChecksumAlg = "crc32c"
)

type checksumCacheKey struct {
	alg    ChecksumAlg
	start  int
	end    int // exclusive coverage end before field, or -1 for whole-before
	width  int
	endian string
}

// ChecksumPass tests common checksums with staged search + caching.
type ChecksumPass struct {
	cache map[checksumCacheKey]uint64
}

func (c *ChecksumPass) Name() string { return "checksums" }

func (c *ChecksumPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if !in.Config.EnableChecksum || in.Dataset == nil || in.Dataset.Len() == 0 {
		return out, nil
	}
	if c.cache == nil {
		c.cache = make(map[checksumCacheKey]uint64)
	}
	ds := in.Dataset
	maxLen := ds.MaxLen()
	minLen := ds.MinLen()
	if minLen < 3 {
		return out, nil
	}

	algs := []ChecksumAlg{AlgXOR8, AlgSUM8, AlgCRC8, AlgSUM16, AlgFletcher16, AlgCRC16CCITT, AlgCRC16IBM, AlgSUM32, AlgAdler32, AlgCRC32IEEE, AlgFletcher32}
	if in.Budget == wt.BudgetQuick {
		algs = []ChecksumAlg{AlgXOR8, AlgSUM8, AlgCRC8, AlgSUM16, AlgCRC16CCITT, AlgCRC32IEEE}
	}
	if in.Budget == wt.BudgetExhaustive {
		algs = append(algs, AlgCRC32C)
	}

	var hyps []wt.Hypothesis
	tried := 0
	maxTrials := 2000
	switch in.Budget {
	case wt.BudgetQuick:
		maxTrials = 400
	case wt.BudgetExhaustive:
		maxTrials = 20000
	}
	// Stage 1: trailer checksums (last 1/2/4 bytes covering prefix)
	trailers := []int{1, 2, 4}
	if in.Budget == wt.BudgetQuick {
		trailers = []int{1, 2}
	}
	for _, width := range trailers {
		if minLen <= width {
			continue
		}
		for _, alg := range algs {
			if algWidth(alg) != width {
				continue
			}
			for _, endian := range endiansFor(width) {
				select {
				case <-ctx.Done():
					out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
					return out, ctx.Err()
				default:
				}
				off := -1 // relative trailer — per message at len-width
				matches, total := 0, 0
				for _, m := range ds.Messages {
					if len(m.Data) <= width {
						continue
					}
					fieldOff := len(m.Data) - width
					want, ok := readU(m.Data[fieldOff:fieldOff+width], endian)
					if !ok {
						continue
					}
					got := c.compute(alg, m.Data[:fieldOff], width, endian)
					total++
					if got == want {
						matches++
					}
				}
				if total < 2 {
					continue
				}
				ratio := float64(matches) / float64(total)
				if ratio < 0.95 {
					continue
				}
				ev := []wt.EvidenceItem{{
					Kind: "support", Description: fmt.Sprintf("%s over [0:len-%d] matches trailer", alg, width),
					Weight: 5, Metric: "match_ratio", Value: ratio,
				}}
				hyps = append(hyps, wt.Hypothesis{
					ID:   fmt.Sprintf("csum_trailer_%s_%s_w%d", alg, endian, width),
					Kind: "checksum", Offset: off, Length: width,
					Description: fmt.Sprintf("trailer %s (%s)", alg, endian),
					Params:      map[string]any{"alg": string(alg), "endian": endian, "coverage": "prefix", "placement": "trailer"},
					Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
				})
			}
		}
	}

	// Stage 2: fixed offsets near end for constant-length messages
	if ds.MaxLen() == ds.MinLen() && maxLen >= 4 {
		for _, width := range trailers {
			fieldOff := maxLen - width
			for _, alg := range algs {
				if algWidth(alg) != width {
					continue
				}
				for _, endian := range endiansFor(width) {
					matches, total := 0, 0
					for _, m := range ds.Messages {
						if len(m.Data) < maxLen {
							continue
						}
						want, _ := readU(m.Data[fieldOff:fieldOff+width], endian)
						got := c.compute(alg, m.Data[:fieldOff], width, endian)
						total++
						if got == want {
							matches++
						}
					}
					if total < 2 {
						continue
					}
					ratio := float64(matches) / float64(total)
					if ratio < 0.95 {
						continue
					}
					ev := []wt.EvidenceItem{{
						Kind: "support", Description: fmt.Sprintf("%s matches at fixed offset %d", alg, fieldOff),
						Weight: 5, Metric: "match_ratio", Value: ratio,
					}}
					hyps = append(hyps, wt.Hypothesis{
						ID:   fmt.Sprintf("csum_o%d_%s_%s", fieldOff, alg, endian),
						Kind: "checksum", Offset: fieldOff, Length: width,
						Description: fmt.Sprintf("%s at offset %d (%s)", alg, fieldOff, endian),
						Params:      map[string]any{"alg": string(alg), "endian": endian, "coverage": "prefix", "placement": "fixed"},
						Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
					})
				}
			}
		}
	}

	// Stage 3 (normal+): header checksum after byte 0..8 covering rest-except-field — limited
	if in.Budget != wt.BudgetQuick && minLen >= 8 {
		for off := 0; off <= 4; off++ {
			for _, width := range []int{1, 2, 4} {
				if off+width > minLen {
					continue
				}
				for _, alg := range algs {
					if algWidth(alg) != width {
						continue
					}
					for _, endian := range endiansFor(width) {
						if tried >= maxTrials {
							out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
							return out, nil
						}
						tried++
						matches, total := 0, 0
						for _, m := range ds.Messages {
							if off+width > len(m.Data) {
								continue
							}
							want, _ := readU(m.Data[off:off+width], endian)
							got := c.compute(alg, m.Data[off+width:], width, endian)
							total++
							if got == want {
								matches++
							}
						}
						if total < 2 {
							continue
						}
						ratio := float64(matches) / float64(total)
						if ratio < 0.95 {
							continue
						}
						ev := []wt.EvidenceItem{{
							Kind: "support", Description: fmt.Sprintf("%s over suffix matches field at %d", alg, off),
							Weight: 4, Metric: "match_ratio", Value: ratio,
						}}
						hyps = append(hyps, wt.Hypothesis{
							ID:   fmt.Sprintf("csum_hdr_o%d_%s_%s", off, alg, endian),
							Kind: "checksum", Offset: off, Length: width,
							Description: fmt.Sprintf("header %s at %d covering suffix", alg, off),
							Params:      map[string]any{"alg": string(alg), "endian": endian, "coverage": "suffix", "placement": "header"},
							Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
						})
					}
				}
			}
		}
	}

	// Stage 4 (normal+): mid-packet field covering prefix exclude / suffix exclude windows
	if in.Budget != wt.BudgetQuick && minLen >= 10 {
		widths := []int{2, 4}
		if in.Budget == wt.BudgetExhaustive {
			widths = []int{1, 2, 4}
		}
		step := 2
		if in.Budget == wt.BudgetExhaustive {
			step = 1
		}
		for _, width := range widths {
			for off := 2; off+width < minLen-1; off += step {
				if tried >= maxTrials {
					break
				}
				for _, alg := range algs {
					if algWidth(alg) != width {
						continue
					}
					for _, endian := range endiansFor(width) {
						if tried >= maxTrials {
							break
						}
						tried++
						// coverage: all bytes except the field itself
						matches, total := 0, 0
						for _, m := range ds.Messages {
							if off+width > len(m.Data) {
								continue
							}
							want, _ := readU(m.Data[off:off+width], endian)
							cov := append(append([]byte(nil), m.Data[:off]...), m.Data[off+width:]...)
							got := c.compute(alg, cov, width, endian)
							total++
							if got == want {
								matches++
							}
						}
						if total < 2 {
							continue
						}
						ratio := float64(matches) / float64(total)
						if ratio < 0.95 {
							continue
						}
						ev := []wt.EvidenceItem{{
							Kind: "support", Description: fmt.Sprintf("%s over all-except-field at %d", alg, off),
							Weight: 4.5, Metric: "match_ratio", Value: ratio,
						}}
						hyps = append(hyps, wt.Hypothesis{
							ID:   fmt.Sprintf("csum_mid_o%d_%s_%s", off, alg, endian),
							Kind: "checksum", Offset: off, Length: width,
							Description: fmt.Sprintf("mid-packet %s at %d (exclude field)", alg, off),
							Params:      map[string]any{"alg": string(alg), "endian": endian, "coverage": "exclude-field", "placement": "mid"},
							Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
						})
					}
				}
			}
		}
	}

	// Stage 5 (exhaustive): prefix-exclude / suffix-exclude small windows
	if in.Budget == wt.BudgetExhaustive && minLen >= 8 {
		for skip := 1; skip <= 4 && tried < maxTrials; skip++ {
			width := 2
			fieldOff := minLen - width
			for _, alg := range algs {
				if algWidth(alg) != width {
					continue
				}
				for _, endian := range endiansFor(width) {
					tried++
					matches, total := 0, 0
					for _, m := range ds.Messages {
						if len(m.Data) < skip+width {
							continue
						}
						fo := len(m.Data) - width
						want, _ := readU(m.Data[fo:fo+width], endian)
						got := c.compute(alg, m.Data[skip:fo], width, endian)
						total++
						if got == want {
							matches++
						}
					}
					if total < 2 {
						continue
					}
					ratio := float64(matches) / float64(total)
					if ratio < 0.95 {
						continue
					}
					ev := []wt.EvidenceItem{{
						Kind: "support", Description: fmt.Sprintf("%s trailer covering [%d:len-%d]", alg, skip, width),
						Weight: 4, Metric: "match_ratio", Value: ratio,
					}}
					hyps = append(hyps, wt.Hypothesis{
						ID:   fmt.Sprintf("csum_prefixexcl_%d_%s_%s", skip, alg, endian),
						Kind: "checksum", Offset: -1, Length: width,
						Description: fmt.Sprintf("trailer %s excluding first %d bytes", alg, skip),
						Params:      map[string]any{"alg": string(alg), "endian": endian, "coverage": "prefix-exclude", "skip": skip},
						Confidence:  wt.DeriveConfidence(ev), Status: "hypothesis",
					})
					_ = fieldOff
				}
			}
		}
	}

	out.Hypotheses = prune(hyps, in.Config.MaxCandidates)
	return out, nil
}

func algWidth(a ChecksumAlg) int {
	switch a {
	case AlgXOR8, AlgSUM8, AlgCRC8:
		return 1
	case AlgSUM16, AlgFletcher16, AlgCRC16IBM, AlgCRC16CCITT:
		return 2
	case AlgSUM32, AlgFletcher32, AlgAdler32, AlgCRC32IEEE, AlgCRC32C:
		return 4
	default:
		return 0
	}
}

func endiansFor(width int) []string {
	if width == 1 {
		return []string{"le"}
	}
	return []string{"be", "le"}
}

func (c *ChecksumPass) compute(alg ChecksumAlg, data []byte, width int, endian string) uint64 {
	// Content-addressed cache: key includes data fingerprint so repeated coverage windows reuse work.
	sum := hash64(data)
	key := checksumCacheKey{alg: alg, start: int(sum >> 32), end: int(sum & 0xffffffff), width: width, endian: endian}
	if c.cache != nil {
		if v, ok := c.cache[key]; ok {
			return v
		}
	}
	v := c.computeUncached(alg, data, width, endian)
	if c.cache != nil {
		c.cache[key] = v
	}
	return v
}

func hash64(data []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, b := range data {
		h ^= uint64(b)
		h *= 1099511628211
	}
	h ^= uint64(len(data)) * 0x9e3779b97f4a7c15
	return h
}

func (c *ChecksumPass) computeUncached(alg ChecksumAlg, data []byte, width int, endian string) uint64 {
	switch alg {
	case AlgXOR8:
		var x byte
		for _, b := range data {
			x ^= b
		}
		return uint64(x)
	case AlgSUM8:
		var s uint32
		for _, b := range data {
			s += uint32(b)
		}
		return uint64(byte(s))
	case AlgSUM16:
		var s uint32
		for _, b := range data {
			s += uint32(b)
		}
		v := uint16(s)
		return endianU16(v, endian)
	case AlgSUM32:
		var s uint64
		for _, b := range data {
			s += uint64(b)
		}
		return endianU32(uint32(s), endian)
	case AlgFletcher16:
		return endianU16(fletcher16(data), endian)
	case AlgFletcher32:
		return endianU32(fletcher32(data), endian)
	case AlgAdler32:
		return endianU32(adler32.Checksum(data), endian)
	case AlgCRC8:
		return uint64(crc8(data))
	case AlgCRC16IBM:
		return endianU16(crc16IBM(data), endian)
	case AlgCRC16CCITT:
		return endianU16(crc16CCITT(data), endian)
	case AlgCRC32IEEE:
		return endianU32(crc32.ChecksumIEEE(data), endian)
	case AlgCRC32C:
		return endianU32(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)), endian)
	default:
		_ = crc64.Checksum
		return 0
	}
}

func endianU16(v uint16, endian string) uint64 {
	var b [2]byte
	if endian == "le" {
		binary.LittleEndian.PutUint16(b[:], v)
		return uint64(binary.LittleEndian.Uint16(b[:]))
	}
	binary.BigEndian.PutUint16(b[:], v)
	return uint64(binary.BigEndian.Uint16(b[:]))
}

func endianU32(v uint32, endian string) uint64 {
	return uint64(v) // numeric compare; field read already endian-decoded
}

func fletcher16(data []byte) uint16 {
	var sum1, sum2 uint16
	for _, b := range data {
		sum1 = (sum1 + uint16(b)) % 255
		sum2 = (sum2 + sum1) % 255
	}
	return (sum2 << 8) | sum1
}

func fletcher32(data []byte) uint32 {
	var sum1, sum2 uint32
	for i := 0; i+1 < len(data); i += 2 {
		word := uint32(data[i]) | uint32(data[i+1])<<8
		sum1 = (sum1 + word) % 65535
		sum2 = (sum2 + sum1) % 65535
	}
	if len(data)%2 == 1 {
		sum1 = (sum1 + uint32(data[len(data)-1])) % 65535
		sum2 = (sum2 + sum1) % 65535
	}
	return (sum2 << 16) | sum1
}

func crc8(data []byte) byte {
	var crc byte
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func crc16IBM(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func crc16CCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ComputeChecksum is exported for tests/fuzz.
func ComputeChecksum(alg ChecksumAlg, data []byte) uint64 {
	p := &ChecksumPass{}
	return p.compute(alg, data, algWidth(alg), "be")
}
