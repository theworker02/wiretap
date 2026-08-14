package capture

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func init() {
	wt.RegisterIngest(
		ParseAuto,
		func(hexes []string) (*wt.Dataset, error) {
			return LoadHexStrings(hexes, "hex")
		},
		func(path string, opts wt.IngestOptions) (*wt.Dataset, error) {
			return LoadPath(path, fromPublic(opts))
		},
		func(path string, opts wt.IngestOptions) (*wt.Dataset, error) {
			return LoadPath(path, fromPublic(opts))
		},
		func(path string, opts wt.IngestOptions) (*wt.Dataset, error) {
			return LoadPath(path, fromPublic(opts))
		},
		func(r io.Reader, name string, opts wt.IngestOptions) (*wt.Dataset, error) {
			return LoadReader(r, name, fromPublic(opts))
		},
	)
}

func fromPublic(o wt.IngestOptions) LoadOptions {
	return LoadOptions{
		Binary:         o.Binary,
		OnePerLine:     o.OnePerLine,
		MaxRecordBytes: o.MaxRecordBytes,
		MaxMessages:    o.MaxMessages,
	}
}

// AnalyzeFromPaths loads many paths with bounded memory for message metadata.
// When MaxMessages is hit, remaining files are skipped and truncation is recorded
// in Dataset.Meta (never silently dropped).
func AnalyzeFromPaths(paths []string, opts LoadOptions) (*wt.Dataset, error) {
	ds := wt.NewDataset("multi")
	loaded := 0
	truncated := false
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			part, err := LoadPath(p, opts)
			if err != nil {
				return nil, err
			}
			for _, m := range part.Messages {
				if opts.MaxMessages > 0 && loaded >= opts.MaxMessages {
					truncated = true
					break
				}
				if err := ds.Add(m); err != nil {
					return nil, err
				}
				loaded++
			}
			if truncated {
				break
			}
			continue
		}
		if opts.MaxMessages > 0 && loaded >= opts.MaxMessages {
			truncated = true
			break
		}
		part, err := LoadPath(p, opts)
		if err != nil {
			return nil, err
		}
		for _, m := range part.Messages {
			if opts.MaxMessages > 0 && loaded >= opts.MaxMessages {
				truncated = true
				break
			}
			if err := ds.Add(m); err != nil {
				return nil, err
			}
			loaded++
		}
		if truncated {
			break
		}
	}
	if truncated {
		markTruncated(ds, "max_messages", loaded)
	}
	return ds, nil
}

func markTruncated(ds *wt.Dataset, reason string, loaded int) {
	if ds.Meta == nil {
		ds.Meta = map[string]string{}
	}
	ds.Meta["truncated"] = "true"
	ds.Meta["truncated_reason"] = reason
	ds.Meta["messages_loaded"] = itoa(loaded)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// MessageHandler is called for each ingested message during streaming iterate.
type MessageHandler func(m *wt.Message) error

// IteratePath walks a file or directory and invokes h for each message without
// requiring the caller to hold the full dataset (handler may still retain messages).
func IteratePath(path string, opts LoadOptions, h MessageHandler) error {
	if h == nil {
		return wt.ErrInvalidConfig
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	count := 0
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".labels.yaml") || strings.HasSuffix(lower, ".md") || strings.HasPrefix(name, ".") {
				continue
			}
			fp := filepath.Join(path, name)
			part, err := LoadPath(fp, opts)
			if err != nil {
				return err
			}
			for _, m := range part.Messages {
				if opts.MaxMessages > 0 && count >= opts.MaxMessages {
					return nil
				}
				if err := h(m); err != nil {
					return err
				}
				count++
			}
		}
		return nil
	}
	part, err := LoadPath(path, opts)
	if err != nil {
		return err
	}
	for _, m := range part.Messages {
		if opts.MaxMessages > 0 && count >= opts.MaxMessages {
			return nil
		}
		if err := h(m); err != nil {
			return err
		}
		count++
	}
	return nil
}
