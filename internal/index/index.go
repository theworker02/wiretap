package index

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// Entry is one indexed sample.
type Entry struct {
	ID     string            `json:"id"`
	Length int               `json:"length"`
	Hash   string            `json:"hash"`
	Path   string            `json:"path,omitempty"`
	Offset int64             `json:"offset,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Index is an on-disk sample index for incremental analyze.
type Index struct {
	Version     string            `json:"version"`
	Created     time.Time         `json:"created"`
	Updated     time.Time         `json:"updated"`
	Fingerprint string            `json:"dataset_fingerprint"`
	Entries     []Entry           `json:"entries"`
	Meta        map[string]string `json:"meta,omitempty"`
}

const indexVersion = "1.0.0"

// Build constructs an index from a dataset.
func Build(ds *wt.Dataset) *Index {
	now := time.Now().UTC()
	idx := &Index{
		Version:     indexVersion,
		Created:     now,
		Updated:     now,
		Fingerprint: ds.Fingerprint(),
		Meta:        map[string]string{},
	}
	if ds != nil {
		idx.Meta["name"] = ds.Name
		for _, m := range ds.Messages {
			sum := sha256.Sum256(m.Data)
			idx.Entries = append(idx.Entries, Entry{
				ID: m.ID, Length: len(m.Data), Hash: hex.EncodeToString(sum[:]),
				Path: m.Source.Path, Offset: m.Source.Offset, Labels: m.Labels,
			})
		}
	}
	sort.Slice(idx.Entries, func(i, j int) bool { return idx.Entries[i].ID < idx.Entries[j].ID })
	return idx
}

// Save writes index JSON to path.
func Save(idx *Index, path string) error {
	if idx == nil {
		return wt.ErrNotFound
	}
	idx.Updated = time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Load reads an index from path.
func Load(path string) (*Index, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("%w: %v", wt.ErrInvalidConfig, err)
	}
	return &idx, nil
}

// Diff reports entries that are new or changed vs previous index.
type DiffResult struct {
	New       []Entry `json:"new"`
	Changed   []Entry `json:"changed"`
	Unchanged []Entry `json:"unchanged"`
	Removed   []Entry `json:"removed"`
}

// Diff compares old and new indexes by message id + content hash.
func Diff(old, neu *Index) DiffResult {
	var d DiffResult
	oldMap := map[string]Entry{}
	if old != nil {
		for _, e := range old.Entries {
			oldMap[e.ID] = e
		}
	}
	seen := map[string]bool{}
	if neu != nil {
		for _, e := range neu.Entries {
			seen[e.ID] = true
			prev, ok := oldMap[e.ID]
			if !ok {
				d.New = append(d.New, e)
				continue
			}
			if prev.Hash != e.Hash {
				d.Changed = append(d.Changed, e)
			} else {
				d.Unchanged = append(d.Unchanged, e)
			}
		}
	}
	for id, e := range oldMap {
		if !seen[id] {
			d.Removed = append(d.Removed, e)
		}
	}
	return d
}

// NeedsAnalyze is true when fingerprint changed or any sample is new/changed.
func NeedsAnalyze(old, neu *Index) bool {
	if old == nil || neu == nil {
		return true
	}
	if old.Fingerprint != neu.Fingerprint {
		return true
	}
	d := Diff(old, neu)
	return len(d.New) > 0 || len(d.Changed) > 0 || len(d.Removed) > 0
}

// DefaultPath returns project index path.
func DefaultPath(projectRoot string) string {
	return filepath.Join(projectRoot, "reports", "index.json")
}

// FilterDataset returns messages whose IDs are in new/changed sets.
func FilterDataset(ds *wt.Dataset, d DiffResult) *wt.Dataset {
	want := map[string]bool{}
	for _, e := range d.New {
		want[e.ID] = true
	}
	for _, e := range d.Changed {
		want[e.ID] = true
	}
	out := wt.NewDataset(ds.Name + "_incremental")
	for _, m := range ds.Messages {
		if want[m.ID] {
			_ = out.Add(m)
		}
	}
	return out
}
