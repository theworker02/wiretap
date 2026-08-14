package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/theworker02/wiretap/internal/capture"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

const ConfigName = "wiretap.yaml"

// Config is the project configuration file.
type Config struct {
	Name        string            `yaml:"name" json:"name"`
	CreatedAt   string            `yaml:"created_at" json:"created_at"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Meta        map[string]string `yaml:"meta,omitempty" json:"meta,omitempty"`
}

// Annotation is a human note that is never auto-overwritten.
type Annotation struct {
	ID        string            `yaml:"id" json:"id"`
	Offset    int               `yaml:"offset" json:"offset"`
	Length    int               `yaml:"length" json:"length"`
	Kind      string            `yaml:"kind" json:"kind"`
	Label     string            `yaml:"label" json:"label"`
	Note      string            `yaml:"note,omitempty" json:"note,omitempty"`
	CreatedAt string            `yaml:"created_at" json:"created_at"`
	Meta      map[string]string `yaml:"meta,omitempty" json:"meta,omitempty"`
}

// Init creates a new project directory structure.
func Init(dir, name string) error {
	if name == "" {
		name = filepath.Base(dir)
	}
	if _, err := os.Stat(filepath.Join(dir, ConfigName)); err == nil {
		return fmt.Errorf("%w: %s", wt.ErrProjectExists, dir)
	}
	for _, sub := range []string{"samples", "experiments", "annotations", "schemas", "reports", "notes"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return err
		}
	}
	cfg := Config{
		Name:      name,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Meta:      map[string]string{"wiretap": "0.4.0"},
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	header := "# Wiretap project configuration\n# Human annotations live in annotations/ and are never overwritten by analysis.\n"
	return os.WriteFile(filepath.Join(dir, ConfigName), append([]byte(header), b...), 0o644)
}

// FindRoot walks up looking for wiretap.yaml.
func FindRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ConfigName)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", wt.ErrNoProject
		}
		dir = parent
	}
}

// LoadConfig loads wiretap.yaml from a project root.
func LoadConfig(root string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(root, ConfigName))
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// AddSample copies or writes a sample into samples/ with optional labels sidecar.
// Captured-at metadata is recorded from the source file mtime when available.
func AddSample(root, srcPath string, labels map[string]string) (string, error) {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", err
	}
	base := filepath.Base(srcPath)
	dst := filepath.Join(root, "samples", base)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", err
	}
	meta := map[string]string{}
	for k, v := range labels {
		meta[k] = v
	}
	if info, err := os.Stat(srcPath); err == nil {
		meta["captured_at"] = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	if len(meta) > 0 {
		metaPath := dst + ".labels.yaml"
		b, err := yaml.Marshal(meta)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(metaPath, b, 0o644); err != nil {
			return "", err
		}
	}
	return dst, nil
}

// AddSampleHex writes a hex sample file.
func AddSampleHex(root, name, hex string, labels map[string]string) (string, error) {
	if _, err := capture.ParseAuto(hex); err != nil {
		return "", err
	}
	if !strings.HasSuffix(name, ".hex") {
		name += ".hex"
	}
	dst := filepath.Join(root, "samples", name)
	if err := os.WriteFile(dst, []byte(hex+"\n"), 0o644); err != nil {
		return "", err
	}
	if len(labels) > 0 {
		b, _ := yaml.Marshal(labels)
		_ = os.WriteFile(dst+".labels.yaml", b, 0o644)
	}
	return dst, nil
}

// LoadSamples loads all samples from the project with labels.
func LoadSamples(root string) (*wt.Dataset, error) {
	dir := filepath.Join(root, "samples")
	ds, err := capture.LoadPath(dir, capture.LoadOptions{OnePerLine: true})
	if err != nil {
		return nil, err
	}
	// Attach labels from sidecars
	for _, m := range ds.Messages {
		path := m.Source.Path
		if path == "" {
			continue
		}
		lb := path + ".labels.yaml"
		b, err := os.ReadFile(lb)
		if err != nil {
			continue
		}
		var labels map[string]string
		if yaml.Unmarshal(b, &labels) == nil {
			for k, v := range labels {
				if k == "captured_at" {
					if ts, err := time.Parse(time.RFC3339Nano, v); err == nil {
						t := ts.UTC()
						m.Captured = &t
					} else if ts, err := time.Parse(time.RFC3339, v); err == nil {
						t := ts.UTC()
						m.Captured = &t
					}
					continue
				}
				m.Labels[k] = v
			}
		}
	}
	cfg, _ := LoadConfig(root)
	if cfg != nil {
		ds.Name = cfg.Name
	}
	return ds, nil
}

// Annotate appends an annotation file (never overwrites existing IDs).
func Annotate(root string, a Annotation) (string, error) {
	if a.ID == "" {
		a.ID = fmt.Sprintf("ann_%d", time.Now().UnixNano())
	}
	if a.CreatedAt == "" {
		a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	dir := filepath.Join(root, "annotations")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, a.ID+".yaml")
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("annotation %s already exists (refusing to overwrite)", a.ID)
	}
	b, err := yaml.Marshal(a)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Unannotate removes an annotation by ID.
func Unannotate(root, id string) error {
	path := filepath.Join(root, "annotations", id+".yaml")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%w: annotation %s", wt.ErrNotFound, id)
	}
	return os.Remove(path)
}

// ListAnnotations loads all annotations.
func ListAnnotations(root string) ([]Annotation, error) {
	dir := filepath.Join(root, "annotations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Annotation
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var a Annotation
		if yaml.Unmarshal(b, &a) == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// SampleInfo describes a file in samples/.
type SampleInfo struct {
	Name   string            `json:"name"`
	Path   string            `json:"path"`
	Bytes  int64             `json:"bytes"`
	Labels map[string]string `json:"labels,omitempty"`
}

// ListSamples lists sample files (not label sidecars) under samples/.
func ListSamples(root string) ([]SampleInfo, error) {
	dir := filepath.Join(root, "samples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SampleInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".labels.yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		info := SampleInfo{Name: name, Path: path, Labels: map[string]string{}}
		if fi, err := e.Info(); err == nil {
			info.Bytes = fi.Size()
		}
		if b, err := os.ReadFile(path + ".labels.yaml"); err == nil {
			_ = yaml.Unmarshal(b, &info.Labels)
		}
		out = append(out, info)
	}
	return out, nil
}

// RemoveSample deletes a sample and its labels sidecar by file name or path.
func RemoveSample(root, name string) error {
	base := filepath.Base(name)
	path := filepath.Join(root, "samples", base)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%w: sample %s", wt.ErrNotFound, base)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	_ = os.Remove(path + ".labels.yaml")
	return nil
}

// SetSampleLabels merges labels into a sample's sidecar (creates if missing).
func SetSampleLabels(root, name string, labels map[string]string) error {
	base := filepath.Base(name)
	path := filepath.Join(root, "samples", base)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%w: sample %s", wt.ErrNotFound, base)
	}
	meta := map[string]string{}
	lb := path + ".labels.yaml"
	if b, err := os.ReadFile(lb); err == nil {
		_ = yaml.Unmarshal(b, &meta)
	}
	for k, v := range labels {
		meta[k] = v
	}
	b, err := yaml.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(lb, b, 0o644)
}

// Tree lists the standard project directory layout with entry counts.
func Tree(root string) (map[string]int, error) {
	out := map[string]int{}
	for _, sub := range []string{"samples", "experiments", "annotations", "schemas", "reports", "notes"} {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				out[sub] = 0
				continue
			}
			return nil, err
		}
		n := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if sub == "samples" && strings.HasSuffix(e.Name(), ".labels.yaml") {
				continue
			}
			n++
		}
		out[sub] = n
	}
	return out, nil
}
