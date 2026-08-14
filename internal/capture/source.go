package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// CaptureSource is an authorized capture acquisition adapter.
// Analysis is separate: sources only load bytes the operator is allowed to study.
// Wiretap does not MITM, bypass auth, or remotely exploit — authorized use only.
type CaptureSource interface {
	Name() string
	Load(opts LoadOptions) (*wt.Dataset, error)
}

// WatchOptions configures directory drop / watch ingestion.
type WatchOptions struct {
	LoadOptions
	Once       bool          // single scan (default for --once)
	Extensions []string      // default: .bin .hex .pcap .pcapng
	Settle     time.Duration // ignore files newer than this (still writing)
}

// LoadDropDir loads all supported capture files from a drop folder (authorized captures only).
func LoadDropDir(dir string, opts LoadOptions) (*wt.Dataset, error) {
	return WatchDir(dir, WatchOptions{LoadOptions: opts, Once: true})
}

// WatchDir scans a directory for capture files. With Once=true it performs a single pass.
// Live polling loops are left to the CLI (`wiretap watch`); this helper is the one-shot core.
func WatchDir(dir string, opts WatchOptions) (*wt.Dataset, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	exts := opts.Extensions
	if len(exts) == 0 {
		exts = []string{".bin", ".hex", ".pcap", ".pcapng"}
	}
	allow := map[string]bool{}
	for _, e := range exts {
		allow[strings.ToLower(e)] = true
	}
	ds := wt.NewDataset(filepath.Base(dir))
	ds.Meta["source"] = "drop-dir"
	ds.Meta["authorized"] = "operator-provided"
	settle := opts.Settle
	if settle == 0 {
		settle = 500 * time.Millisecond
	}
	now := time.Now()
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if !allow[ext] {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := ent.Info()
		if err == nil && now.Sub(info.ModTime()) < settle && !opts.Once {
			continue
		}
		var part *wt.Dataset
		switch ext {
		case ".pcap", ".pcapng":
			part, err = ImportPCAP(path, opts.LoadOptions)
		case ".bin":
			part, err = LoadPath(path, LoadOptions{Binary: true, MaxMessages: opts.MaxMessages, MaxRecordBytes: opts.MaxRecordBytes})
		default:
			part, err = LoadPath(path, opts.LoadOptions)
		}
		if err != nil {
			ds.Meta["warn_"+name] = err.Error()
			continue
		}
		for _, m := range part.Messages {
			m.ID = fmt.Sprintf("%s_%s", strings.TrimSuffix(name, ext), m.ID)
			m.Source.Path = path
			if err := ds.Add(m); err != nil {
				// duplicate ids — remint
				m.ID = fmt.Sprintf("%s_%d", m.ID, ds.Len())
				_ = ds.Add(m)
			}
		}
	}
	if ds.Len() == 0 {
		return nil, fmt.Errorf("%w: no captures in %s", wt.ErrNoMessages, dir)
	}
	return ds, nil
}

// DirSource implements CaptureSource for a drop folder.
type DirSource struct {
	Dir  string
	Opts WatchOptions
}

func (d DirSource) Name() string { return "dir:" + d.Dir }

func (d DirSource) Load(opts LoadOptions) (*wt.Dataset, error) {
	w := d.Opts
	w.LoadOptions = opts
	if w.Once || true {
		w.Once = true
	}
	return WatchDir(d.Dir, w)
}

// StdinFramedSource reads length-prefixed frames: u32be length + payload (authorized stdin).
type StdinFramedSource struct {
	R interface {
		Read([]byte) (int, error)
	}
}

func (s StdinFramedSource) Name() string { return "stdin-framed" }

func (s StdinFramedSource) Load(opts LoadOptions) (*wt.Dataset, error) {
	if s.R == nil {
		return nil, fmt.Errorf("%w: nil reader", wt.ErrInvalidConfig)
	}
	return LoadReader(s.R, "stdin-framed", opts)
}
