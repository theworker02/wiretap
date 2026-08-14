package wiretap

// ReportVersion is the versioned JSON report shape.
const ReportVersion = "1.0.0"

// ByteStat is per-offset statistics (observation).
type ByteStat struct {
	Offset              int      `json:"offset"`
	Count               int      `json:"count"`
	Unique              int      `json:"unique"`
	Min                 byte     `json:"min"`
	Max                 byte     `json:"max"`
	Mean                float64  `json:"mean"`
	Median              float64  `json:"median"`
	Mode                byte     `json:"mode"`
	ModeCount           int      `json:"mode_count"`
	Variance            float64  `json:"variance"`
	StdDev              float64  `json:"stddev"`
	Entropy             float64  `json:"entropy"`
	ChangeFrequency     float64  `json:"change_frequency"`
	ConstantProbability float64  `json:"constant_probability"`
	Histogram           [256]int `json:"-"`
}

// Region describes a contiguous byte range with shared properties.
type Region struct {
	Start       int                `json:"start"`
	End         int                `json:"end"`
	Kind        string             `json:"kind"`
	EntropyMean float64            `json:"entropy_mean"`
	Value       *byte              `json:"value,omitempty"`
	Confidence  Confidence         `json:"confidence"`
	Metrics     map[string]float64 `json:"metrics,omitempty"`
}

// Result is the structured analysis report.
type Result struct {
	SchemaVersion      string            `json:"schema_version"`
	ToolVersion        string            `json:"tool_version,omitempty"`
	ToolCommit         string            `json:"tool_commit,omitempty"`
	DatasetName        string            `json:"dataset_name,omitempty"`
	DatasetFingerprint string            `json:"dataset_fingerprint"`
	ConfigFingerprint  string            `json:"config_fingerprint"`
	Budget             string            `json:"budget"`
	MessageCount       int               `json:"message_count"`
	MinLength          int               `json:"min_length"`
	MaxLength          int               `json:"max_length"`
	ByteStatsSummary   []Observation     `json:"byte_stats_summary,omitempty"`
	Stats              []ByteStat        `json:"stats,omitempty"`
	Regions            []Region          `json:"regions,omitempty"`
	Constants          []Region          `json:"constants,omitempty"`
	Observations       []Observation     `json:"observations"`
	Hypotheses         []Hypothesis      `json:"hypotheses"`
	Warnings           []string          `json:"warnings,omitempty"`
	Truncated          bool              `json:"truncated,omitempty"`
	ElapsedMS          int64             `json:"elapsed_ms"`
	ElapsedUS          int64             `json:"elapsed_us"`
	Meta               map[string]string `json:"meta,omitempty"`
}

// SetElapsed records wall time with microsecond resolution.
// ElapsedMS is rounded from microseconds and is at least 1 when any work occurred (≥500µs).
func (r *Result) SetElapsed(d interface{ Microseconds() int64 }) {
	if r == nil || d == nil {
		return
	}
	us := d.Microseconds()
	if us < 0 {
		us = 0
	}
	r.ElapsedUS = us
	ms := us / 1000
	if us >= 500 && ms == 0 {
		ms = 1
	}
	r.ElapsedMS = ms
}
