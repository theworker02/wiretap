package wiretap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Budget controls how thoroughly the analyzer searches.
type Budget string

const (
	BudgetQuick      Budget = "quick"
	BudgetNormal     Budget = "normal"
	BudgetExhaustive Budget = "exhaustive"
)

// Source describes where a message came from (observation, not inference).
type Source struct {
	Kind     string `json:"kind"` // file, stdin, hex, raw, directory
	Path     string `json:"path,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
	Line     int    `json:"line,omitempty"`
	Imported string `json:"imported,omitempty"`
}

// Message is one binary record with a stable ID (never an array index alone).
type Message struct {
	ID        string            `json:"id"`
	Data      []byte            `json:"-"`
	Hex       string            `json:"hex,omitempty"` // optional serialization aid
	Source    Source            `json:"source"`
	Labels    map[string]string `json:"labels,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Captured  *time.Time        `json:"captured,omitempty"`
	Truncated bool              `json:"truncated,omitempty"`
}

// Bytes returns the message payload.
func (m *Message) Bytes() []byte {
	if m == nil {
		return nil
	}
	return m.Data
}

// Dataset is a collection of messages with stable identity and fingerprints.
type Dataset struct {
	Name     string            `json:"name,omitempty"`
	Messages []*Message        `json:"messages"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// NewDataset creates an empty dataset.
func NewDataset(name string) *Dataset {
	return &Dataset{
		Name:     name,
		Messages: make([]*Message, 0),
		Meta:     make(map[string]string),
	}
}

// Add appends a message. ID must be unique and non-empty.
func (d *Dataset) Add(m *Message) error {
	if d == nil {
		return ErrEmptyDataset
	}
	if m == nil || len(m.Data) == 0 && m.Hex == "" {
		return fmt.Errorf("%w: empty message", ErrNoMessages)
	}
	if m.ID == "" {
		sum := sha256.Sum256(m.Data)
		m.ID = "msg_" + hex.EncodeToString(sum[:8])
	}
	for _, existing := range d.Messages {
		if existing.ID == m.ID {
			return fmt.Errorf("%w: %s", ErrDuplicateID, m.ID)
		}
	}
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	if m.Metadata == nil {
		m.Metadata = make(map[string]string)
	}
	d.Messages = append(d.Messages, m)
	return nil
}

// Len returns message count.
func (d *Dataset) Len() int {
	if d == nil {
		return 0
	}
	return len(d.Messages)
}

// Fingerprint returns a stable SHA-256 hex of sorted message IDs and payloads.
func (d *Dataset) Fingerprint() string {
	if d == nil || len(d.Messages) == 0 {
		return ""
	}
	type pair struct {
		id   string
		data []byte
	}
	pairs := make([]pair, len(d.Messages))
	for i, m := range d.Messages {
		pairs[i] = pair{id: m.ID, data: m.Data}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].id < pairs[j].id })
	h := sha256.New()
	for _, p := range pairs {
		h.Write([]byte(p.id))
		h.Write([]byte{0})
		h.Write(p.data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MaxLen returns the longest message length.
func (d *Dataset) MaxLen() int {
	max := 0
	for _, m := range d.Messages {
		if n := len(m.Data); n > max {
			max = n
		}
	}
	return max
}

// MinLen returns the shortest message length (0 if empty).
func (d *Dataset) MinLen() int {
	if len(d.Messages) == 0 {
		return 0
	}
	min := len(d.Messages[0].Data)
	for _, m := range d.Messages[1:] {
		if n := len(m.Data); n < min {
			min = n
		}
	}
	return min
}

// ConfidenceLevel is an ordinal strength label derived from evidence weight — not inventable scores.
type ConfidenceLevel string

const (
	ConfidenceUnknown      ConfidenceLevel = "Unknown"
	ConfidenceInsufficient ConfidenceLevel = "Insufficient"
	ConfidenceLow          ConfidenceLevel = "Low"
	ConfidenceMedium       ConfidenceLevel = "Medium"
	ConfidenceHigh         ConfidenceLevel = "High"
)

// EvidenceItem is one measurable supporting or contradicting observation.
type EvidenceItem struct {
	Kind        string  `json:"kind"` // support | contradict | observation
	Description string  `json:"description"`
	Weight      float64 `json:"weight"` // relative contribution; sum of supports drives level
	Metric      string  `json:"metric,omitempty"`
	Value       float64 `json:"value,omitempty"`
}

// Confidence aggregates evidence into an explainable level.
type Confidence struct {
	Level    ConfidenceLevel `json:"level"`
	Score    float64         `json:"score"` // derived 0..1 from evidence weights; Unknown when no evidence
	Evidence []EvidenceItem  `json:"evidence,omitempty"`
	Notes    string          `json:"notes,omitempty"`
}

// DeriveConfidence computes level from evidence weights. Empty evidence => Unknown.
func DeriveConfidence(ev []EvidenceItem) Confidence {
	c := Confidence{Level: ConfidenceUnknown, Evidence: ev}
	if len(ev) == 0 {
		c.Notes = "No measurable evidence recorded"
		return c
	}
	var support, contradict float64
	for _, e := range ev {
		switch e.Kind {
		case "contradict":
			contradict += e.Weight
		default:
			support += e.Weight
		}
	}
	net := support - contradict
	total := support + contradict
	if total <= 0 {
		c.Level = ConfidenceInsufficient
		c.Notes = "Insufficient evidence"
		return c
	}
	if net <= 0 {
		c.Score = 0
		c.Level = ConfidenceInsufficient
		c.Notes = "Contradicting evidence outweighs support"
		return c
	}
	c.Score = net / (net + contradict + 1e-9)
	switch {
	case support >= 4 && c.Score >= 0.85 && contradict < 0.5:
		c.Level = ConfidenceHigh
	case support >= 2 && c.Score >= 0.6:
		c.Level = ConfidenceMedium
	case support >= 0.5:
		c.Level = ConfidenceLow
	default:
		c.Level = ConfidenceInsufficient
		c.Notes = "Insufficient evidence"
	}
	return c
}

// Hypothesis is a competing explanation for a region or field.
type Hypothesis struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"` // integer, string, checksum, length, counter, ...
	Offset      int            `json:"offset"`
	Length      int            `json:"length"`
	Description string         `json:"description"`
	Params      map[string]any `json:"params,omitempty"`
	Confidence  Confidence     `json:"confidence"`
	Status      string         `json:"status"` // hypothesis | observation
	Alternates  []string       `json:"alternates,omitempty"`
}

// Observation is a measured fact (not a guess).
type Observation struct {
	Kind        string         `json:"kind"`
	Offset      int            `json:"offset,omitempty"`
	Length      int            `json:"length,omitempty"`
	Description string         `json:"description"`
	Metrics     map[string]any `json:"metrics,omitempty"`
}

// ConfigFingerprint hashes analysis options for reproducibility.
func ConfigFingerprint(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// LabelKeys returns sorted unique label keys across messages.
func (d *Dataset) LabelKeys() []string {
	seen := map[string]struct{}{}
	for _, m := range d.Messages {
		for k := range m.Labels {
			seen[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// FilterByLabel returns messages where labels[key]==value.
func (d *Dataset) FilterByLabel(key, value string) []*Message {
	out := make([]*Message, 0)
	for _, m := range d.Messages {
		if m.Labels[key] == value {
			out = append(out, m)
		}
	}
	return out
}

// String returns a short dataset summary.
func (d *Dataset) String() string {
	if d == nil {
		return "Dataset<nil>"
	}
	return fmt.Sprintf("Dataset{name=%q messages=%d fingerprint=%s}", d.Name, d.Len(), truncate(d.Fingerprint(), 12))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// NormalizeLabels ensures empty maps are non-nil for JSON stability.
func NormalizeLabels(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// JoinLabels formats labels for display.
func JoinLabels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}
