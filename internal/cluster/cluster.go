package cluster

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// Cluster is a group of similar messages.
type Cluster struct {
	ID           string             `json:"id"`
	MessageIDs   []string           `json:"message_ids"`
	Length       int                `json:"length"`
	ConstantPref []byte             `json:"constant_prefix_hex,omitempty"`
	PrefixLen    int                `json:"prefix_len"`
	Size         int                `json:"size"`
	EntropyMean  float64            `json:"entropy_mean,omitempty"`
	Signals      map[string]float64 `json:"signals,omitempty"`
}

// TypeFieldHypothesis is a candidate type/discriminator field across clusters.
type TypeFieldHypothesis struct {
	Offset      int               `json:"offset"`
	Length      int               `json:"length"`
	Confidence  wt.Confidence     `json:"confidence"`
	Mapping     map[string]string `json:"mapping,omitempty"` // value hex -> cluster id
	Description string            `json:"description"`
}

// SoftMember is an optional soft assignment of a message to a cluster.
type SoftMember struct {
	MessageID string  `json:"message_id"`
	ClusterID string  `json:"cluster_id"`
	Score     float64 `json:"score"`
}

// HierarchyNode is a coarse parent grouping (length → fine clusters).
type HierarchyNode struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Children []string `json:"children"` // cluster ids
}

// Result holds clustering output.
type Result struct {
	Clusters       []Cluster             `json:"clusters"`
	TypeFields     []TypeFieldHypothesis `json:"type_fields,omitempty"`
	SoftMembership []SoftMember          `json:"soft_membership,omitempty"`
	Hierarchy      []HierarchyNode       `json:"hierarchy,omitempty"`
}

// Options for clustering.
type Options struct {
	PrefixLen      int     // constant prefix length to group on (0 = auto)
	SimilarityMin  float64 // 0..1 Hamming similarity for same-length msgs
	MinClusterSize int
	MultiSignal    bool // length+prefix+entropy+histogram distance
	SoftAssign     bool
}

// ClusterMessages groups by length + constant prefix + similarity.
func ClusterMessages(ds *wt.Dataset, opts Options) (*Result, error) {
	if ds == nil || ds.Len() == 0 {
		return nil, wt.ErrEmptyDataset
	}
	if opts.MinClusterSize <= 0 {
		opts.MinClusterSize = 1
	}
	if opts.SimilarityMin < 0 {
		opts.SimilarityMin = 0.85
	}
	// SimilarityMin == 0 disables pairwise splitting (prefix/length grouping only).

	// Group by length first
	byLen := map[int][]*wt.Message{}
	for _, m := range ds.Messages {
		byLen[len(m.Data)] = append(byLen[len(m.Data)], m)
	}
	lengths := make([]int, 0, len(byLen))
	for l := range byLen {
		lengths = append(lengths, l)
	}
	sort.Ints(lengths)

	var clusters []Cluster
	cid := 0
	for _, l := range lengths {
		msgs := byLen[l]
		prefLen := opts.PrefixLen
		if prefLen <= 0 {
			prefLen = commonPrefixLen(msgs)
			if prefLen > 8 {
				prefLen = 8
			}
			if prefLen < 1 && l > 0 {
				prefLen = 1
			}
		}
		if prefLen > l {
			prefLen = l
		}
		// subgroup by prefix
		groups := map[string][]*wt.Message{}
		for _, m := range msgs {
			key := string(m.Data[:prefLen])
			groups[key] = append(groups[key], m)
		}
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			g := groups[k]
			// further split by similarity if needed
			sub := [][]*wt.Message{g}
			if opts.SimilarityMin > 0 {
				sub = similaritySplit(g, opts.SimilarityMin)
			}
			for _, sg := range sub {
				if opts.MultiSignal && len(sg) > 2 {
					sgGroups := multiSignalSplit(sg, 0.75)
					for _, msg := range sgGroups {
						cl := buildCluster(cid, msg, l, prefLen, []byte(k), opts.MinClusterSize)
						if cl == nil {
							continue
						}
						clusters = append(clusters, *cl)
						cid++
					}
					continue
				}
				cl := buildCluster(cid, sg, l, prefLen, []byte(k), opts.MinClusterSize)
				if cl == nil {
					continue
				}
				clusters = append(clusters, *cl)
				cid++
			}
		}
	}

	res := &Result{Clusters: clusters}
	if len(clusters) >= 2 {
		res.TypeFields = discoverTypeFields(ds, clusters)
	}
	// Hierarchy: group by length
	byLenH := map[int][]string{}
	for _, c := range clusters {
		byLenH[c.Length] = append(byLenH[c.Length], c.ID)
	}
	lens := make([]int, 0, len(byLenH))
	for l := range byLenH {
		lens = append(lens, l)
	}
	sort.Ints(lens)
	for _, l := range lens {
		kids := byLenH[l]
		sort.Strings(kids)
		res.Hierarchy = append(res.Hierarchy, HierarchyNode{
			ID: fmt.Sprintf("len_%d", l), Label: fmt.Sprintf("length=%d", l), Children: kids,
		})
	}
	if opts.SoftAssign {
		res.SoftMembership = softAssign(ds, clusters)
	}
	return res, nil
}

func buildCluster(cid int, sg []*wt.Message, l, prefLen int, pref []byte, minSize int) *Cluster {
	if len(sg) < minSize {
		return nil
	}
	ids := make([]string, len(sg))
	entSum := 0.0
	for i, m := range sg {
		ids[i] = m.ID
		entSum += msgEntropy(m.Data)
	}
	sort.Strings(ids)
	return &Cluster{
		ID: fmt.Sprintf("c%d", cid), MessageIDs: ids, Length: l,
		PrefixLen: prefLen, Size: len(sg), ConstantPref: append([]byte(nil), pref...),
		EntropyMean: entSum / float64(len(sg)),
		Signals: map[string]float64{
			"length": float64(l), "prefix_len": float64(prefLen),
			"entropy_mean": entSum / float64(len(sg)),
		},
	}
}

func msgEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	n := float64(len(b))
	H := 0.0
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		H -= p * math.Log2(p)
	}
	return H
}

func multiSignalSplit(msgs []*wt.Message, minSim float64) [][]*wt.Message {
	if len(msgs) <= 1 {
		return [][]*wt.Message{msgs}
	}
	used := make([]bool, len(msgs))
	var out [][]*wt.Message
	for i := range msgs {
		if used[i] {
			continue
		}
		group := []*wt.Message{msgs[i]}
		used[i] = true
		for j := i + 1; j < len(msgs); j++ {
			if used[j] {
				continue
			}
			if multiSignalSim(msgs[i].Data, msgs[j].Data) >= minSim {
				group = append(group, msgs[j])
				used[j] = true
			}
		}
		out = append(out, group)
	}
	return out
}

func multiSignalSim(a, b []byte) float64 {
	ham := hammingSim(a, b)
	hist := histogramSim(a, b)
	ea, eb := msgEntropy(a), msgEntropy(b)
	entSim := 1.0 - math.Min(1, math.Abs(ea-eb)/8.0)
	return 0.5*ham + 0.3*hist + 0.2*entSim
}

func histogramSim(a, b []byte) float64 {
	var ha, hb [256]int
	for _, c := range a {
		ha[c]++
	}
	for _, c := range b {
		hb[c]++
	}
	dot, na, nb := 0.0, 0.0, 0.0
	for i := 0; i < 256; i++ {
		fa, fb := float64(ha[i]), float64(hb[i])
		dot += fa * fb
		na += fa * fa
		nb += fb * fb
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func softAssign(ds *wt.Dataset, clusters []Cluster) []SoftMember {
	idToMsg := map[string]*wt.Message{}
	for _, m := range ds.Messages {
		idToMsg[m.ID] = m
	}
	var out []SoftMember
	for _, m := range ds.Messages {
		bestID := ""
		best := -1.0
		second := -1.0
		for _, c := range clusters {
			if c.Length != len(m.Data) || len(c.MessageIDs) == 0 {
				continue
			}
			ref := idToMsg[c.MessageIDs[0]]
			if ref == nil {
				continue
			}
			s := multiSignalSim(m.Data, ref.Data)
			if s > best {
				second = best
				best = s
				bestID = c.ID
			} else if s > second {
				second = s
			}
		}
		if bestID == "" {
			continue
		}
		out = append(out, SoftMember{MessageID: m.ID, ClusterID: bestID, Score: best})
		if second > 0.6 && second+0.05 >= best {
			// ambiguous — also record runner-up lightly via lower score entry skipped; keep primary only
			_ = second
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MessageID == out[j].MessageID {
			return out[i].ClusterID < out[j].ClusterID
		}
		return out[i].MessageID < out[j].MessageID
	})
	return out
}

func commonPrefixLen(msgs []*wt.Message) int {
	if len(msgs) == 0 {
		return 0
	}
	min := len(msgs[0].Data)
	for _, m := range msgs[1:] {
		if len(m.Data) < min {
			min = len(m.Data)
		}
	}
	n := 0
	for n < min {
		b := msgs[0].Data[n]
		ok := true
		for _, m := range msgs[1:] {
			if m.Data[n] != b {
				ok = false
				break
			}
		}
		if !ok {
			break
		}
		n++
	}
	return n
}

func similaritySplit(msgs []*wt.Message, minSim float64) [][]*wt.Message {
	if len(msgs) <= 1 {
		return [][]*wt.Message{msgs}
	}
	// greedy clustering by pairwise Hamming similarity
	used := make([]bool, len(msgs))
	var out [][]*wt.Message
	for i := range msgs {
		if used[i] {
			continue
		}
		group := []*wt.Message{msgs[i]}
		used[i] = true
		for j := i + 1; j < len(msgs); j++ {
			if used[j] {
				continue
			}
			if hammingSim(msgs[i].Data, msgs[j].Data) >= minSim {
				group = append(group, msgs[j])
				used[j] = true
			}
		}
		out = append(out, group)
	}
	return out
}

func hammingSim(a, b []byte) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	same := 0
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			same++
		}
	}
	return float64(same) / float64(n)
}

func discoverTypeFields(ds *wt.Dataset, clusters []Cluster) []TypeFieldHypothesis {
	idToCluster := map[string]string{}
	for _, c := range clusters {
		for _, id := range c.MessageIDs {
			idToCluster[id] = c.ID
		}
	}
	maxLen := ds.MaxLen()
	var hyps []TypeFieldHypothesis
	// 1-byte discriminators
	for off := 0; off < maxLen && off < 32; off++ {
		if h, ok := typeFieldAt(ds, idToCluster, clusters, off, 1); ok {
			hyps = append(hyps, h)
		}
	}
	// 2/4-byte discriminators
	for _, width := range []int{2, 4} {
		for off := 0; off+width <= maxLen && off < 32; off++ {
			if h, ok := typeFieldAt(ds, idToCluster, clusters, off, width); ok {
				hyps = append(hyps, h)
			}
		}
	}
	return hyps
}

func typeFieldAt(ds *wt.Dataset, idToCluster map[string]string, clusters []Cluster, off, width int) (TypeFieldHypothesis, bool) {
	clusterVal := map[string]string{}
	consistent := true
	for _, m := range ds.Messages {
		cid, ok := idToCluster[m.ID]
		if !ok || off+width > len(m.Data) {
			continue
		}
		var key string
		switch width {
		case 1:
			key = fmt.Sprintf("%02x", m.Data[off])
		case 2:
			key = fmt.Sprintf("%04x", binary.BigEndian.Uint16(m.Data[off:off+2]))
		case 4:
			key = fmt.Sprintf("%08x", binary.BigEndian.Uint32(m.Data[off:off+4]))
		default:
			return TypeFieldHypothesis{}, false
		}
		if prev, ok := clusterVal[cid]; ok && prev != key {
			consistent = false
			break
		}
		clusterVal[cid] = key
	}
	if !consistent || len(clusterVal) < 2 {
		return TypeFieldHypothesis{}, false
	}
	seen := map[string]string{}
	mapping := map[string]string{}
	for cid, v := range clusterVal {
		if other, ok := seen[v]; ok && other != cid {
			return TypeFieldHypothesis{}, false
		}
		seen[v] = cid
		mapping[v] = cid
	}
	if len(seen) < 2 {
		return TypeFieldHypothesis{}, false
	}
	ev := []wt.EvidenceItem{
		{Kind: "support", Description: fmt.Sprintf("constant %d-byte value within cluster, distinct across clusters", width), Weight: 4},
		{Kind: "observation", Description: "type/discriminator field candidate", Weight: 1},
	}
	return TypeFieldHypothesis{
		Offset: off, Length: width, Confidence: wt.DeriveConfidence(ev),
		Mapping:     mapping,
		Description: fmt.Sprintf("possible %d-byte type field at offset %d distinguishing %d clusters", width, off, len(seen)),
	}, true
}
