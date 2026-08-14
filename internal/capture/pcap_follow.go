package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// FollowPCAPOptions configures authorized live follow of a growing PCAP file.
// This tails an operator-provided file on disk — it does not open network
// interfaces, require Npcap, or perform MITM.
type FollowPCAPOptions struct {
	LoadOptions
	PollInterval time.Duration // default 500ms
	IdleTimeout  time.Duration // stop after this much idle growth (0 = single settle then return)
	MaxIdlePolls int           // when IdleTimeout==0, stop after N unchanged polls (default 3)
}

// FollowPCAP re-reads a classic PCAP as it grows (file-tail style).
// Only newly complete packet records are appended. PCAPNG follow is not supported
// (re-import the file when the write finishes). Authorized captures only.
func FollowPCAP(ctx context.Context, path string, opts FollowPCAPOptions) (*wt.Dataset, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	poll := opts.PollInterval
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	maxIdle := opts.MaxIdlePolls
	if maxIdle <= 0 {
		maxIdle = 3
	}

	ds := wt.NewDataset(filepath.Base(path))
	ds.Meta["source"] = "pcap-follow"
	ds.Meta["authorized"] = "operator-provided"
	ds.Meta["path"] = path

	seen := 0
	var lastSize int64
	idle := 0
	deadline := time.Time{}
	if opts.IdleTimeout > 0 {
		deadline = time.Now().Add(opts.IdleTimeout)
	}

	for {
		select {
		case <-ctx.Done():
			if ds.Len() == 0 {
				return nil, ctx.Err()
			}
			return ds, nil
		default:
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		size := info.Size()
		if size < 24 {
			idle++
		} else if size != lastSize {
			part, err := ImportPCAP(path, opts.LoadOptions)
			if err != nil {
				// Incomplete trailing record while writer is still appending — wait.
				if size > lastSize {
					lastSize = size
					idle = 0
					select {
					case <-ctx.Done():
						if ds.Len() == 0 {
							return nil, ctx.Err()
						}
						return ds, nil
					case <-time.After(poll):
					}
					continue
				}
				return nil, err
			}
			for i := seen; i < part.Len(); i++ {
				m := part.Messages[i]
				m.ID = fmt.Sprintf("follow_%s", m.ID)
				m.Source.Imported = "pcap-follow"
				if m.Metadata == nil {
					m.Metadata = map[string]string{}
				}
				m.Metadata["follow"] = "true"
				if opts.MaxMessages > 0 && ds.Len() >= opts.MaxMessages {
					markTruncated(ds, "max_messages", ds.Len())
					return ds, nil
				}
				if err := ds.Add(m); err != nil {
					m.ID = fmt.Sprintf("%s_%d", m.ID, ds.Len())
					_ = ds.Add(m)
				}
			}
			seen = part.Len()
			lastSize = size
			idle = 0
			if opts.IdleTimeout > 0 {
				deadline = time.Now().Add(opts.IdleTimeout)
			}
		} else {
			idle++
		}

		if opts.IdleTimeout > 0 {
			if time.Now().After(deadline) && ds.Len() > 0 {
				return ds, nil
			}
		} else if idle >= maxIdle && ds.Len() > 0 {
			return ds, nil
		} else if idle >= maxIdle && ds.Len() == 0 && size >= 24 {
			// Stable file with no extractable payloads
			return nil, fmt.Errorf("%w: no extractable payloads in pcap follow %s", wt.ErrNoMessages, path)
		}

		select {
		case <-ctx.Done():
			if ds.Len() == 0 {
				return nil, ctx.Err()
			}
			return ds, nil
		case <-time.After(poll):
		}
	}
}
