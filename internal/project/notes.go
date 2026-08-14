package project

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// Note is a project-local research notebook entry (separate from annotations).
// Notes never feed the inference pipeline as trusted evidence.
type Note struct {
	ID        string `yaml:"id" json:"id"`
	Offset    *int   `yaml:"offset,omitempty" json:"offset,omitempty"`
	Text      string `yaml:"text" json:"text"`
	CreatedAt string `yaml:"created_at" json:"created_at"`
	UpdatedAt string `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
}

func notesDir(root string) string {
	return filepath.Join(root, "notes")
}

// AddNote writes a research note. offset may be nil for free-form notes.
func AddNote(root string, offset *int, text string) (*Note, string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, "", fmt.Errorf("%w: note text required", wt.ErrInvalidConfig)
	}
	dir := notesDir(root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", err
	}
	n := &Note{
		ID:        fmt.Sprintf("note_%d_%d", time.Now().UnixNano(), time.Now().UnixMilli()%1000),
		Offset:    offset,
		Text:      text,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	path := filepath.Join(dir, n.ID+".yaml")
	// Avoid rare same-nanosecond collisions on fast consecutive calls.
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(path); err == nil {
			n.ID = fmt.Sprintf("note_%d_%d", time.Now().UnixNano(), i)
			path = filepath.Join(dir, n.ID+".yaml")
			continue
		}
		break
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		return nil, "", err
	}
	header := "# Wiretap research note (not trusted evidence; use annotate for pipeline evidence)\n"
	if err := os.WriteFile(path, append([]byte(header), b...), 0o644); err != nil {
		return nil, "", err
	}
	return n, path, nil
}

// ListNotes loads all research notes (sorted by created_at, then id).
func ListNotes(root string) ([]Note, error) {
	dir := notesDir(root)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Note
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var n Note
		if yaml.Unmarshal(b, &n) == nil && n.ID != "" {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt == out[j].CreatedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt < out[j].CreatedAt
	})
	return out, nil
}

// SearchNotes returns notes whose text (or offset string) contains query (case-insensitive).
func SearchNotes(root, query string) ([]Note, error) {
	all, err := ListNotes(root)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return all, nil
	}
	var out []Note
	for _, n := range all {
		hay := strings.ToLower(n.Text + " " + n.ID)
		if n.Offset != nil {
			hay += fmt.Sprintf(" 0x%x %d", *n.Offset, *n.Offset)
		}
		if strings.Contains(hay, q) {
			out = append(out, n)
		}
	}
	return out, nil
}
