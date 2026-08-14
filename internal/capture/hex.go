package capture

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// HexError reports a precise location for malformed hex input.
type HexError struct {
	Offset  int // byte offset in input string
	Line    int // 1-based if known
	Column  int // 1-based if known
	Snippet string
	Msg     string
}

func (e *HexError) Error() string {
	loc := fmt.Sprintf("offset %d", e.Offset)
	if e.Line > 0 {
		loc = fmt.Sprintf("line %d col %d (offset %d)", e.Line, e.Column, e.Offset)
	}
	if e.Snippet != "" {
		return fmt.Sprintf("%v: %s at %s near %q", wt.ErrInvalidHex, e.Msg, loc, e.Snippet)
	}
	return fmt.Sprintf("%v: %s at %s", wt.ErrInvalidHex, e.Msg, loc)
}

func (e *HexError) Unwrap() error { return wt.ErrInvalidHex }

// ParseHex normalizes and decodes hex tolerant of spaces, colons, dashes, 0x prefixes, and newlines.
// Odd-length nibble streams after stripping separators are an error with location.
func ParseHex(s string) ([]byte, error) {
	if s == "" {
		return nil, &HexError{Msg: "empty input"}
	}
	var out []byte
	var nibble int = -1
	line, col := 1, 0
	i := 0
	for i < len(s) {
		c := s[i]
		col++
		if c == '\n' {
			line++
			col = 0
			i++
			continue
		}
		if c == '\r' {
			i++
			continue
		}
		if unicode.IsSpace(rune(c)) || c == ':' || c == '-' || c == ',' {
			i++
			continue
		}
		// 0x / 0X prefix
		if c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			i += 2
			col++
			continue
		}
		v, ok := fromHex(c)
		if !ok {
			snip := snippet(s, i, 8)
			return nil, &HexError{Offset: i, Line: line, Column: col, Snippet: snip, Msg: fmt.Sprintf("unexpected character %q", c)}
		}
		if nibble < 0 {
			nibble = int(v)
		} else {
			out = append(out, byte(nibble<<4|int(v)))
			nibble = -1
		}
		i++
	}
	if nibble >= 0 {
		return nil, &HexError{Offset: len(s) - 1, Line: line, Column: col, Msg: "odd number of hex digits"}
	}
	if len(out) == 0 {
		return nil, &HexError{Msg: "no hex digits found"}
	}
	return out, nil
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func snippet(s string, i, n int) string {
	start := i
	end := i + n
	if end > len(s) {
		end = len(s)
	}
	return strings.ReplaceAll(s[start:end], "\n", "\\n")
}

// LooksLikeHexDump detects classic hexdump formats (offset | hex | ascii).
func LooksLikeHexDump(s string) bool {
	lines := strings.Split(s, "\n")
	hexLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// offset then hex bytes
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if isHexToken(fields[0]) && isHexToken(fields[1]) {
			hexLines++
		}
	}
	return hexLines >= 2
}

func isHexToken(t string) bool {
	t = strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	if t == "" {
		return false
	}
	for _, c := range t {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ParseHexDump extracts bytes from hexdump-style text (ignores ASCII columns after | or long gaps).
func ParseHexDump(s string) ([]byte, error) {
	var out []byte
	scanner := bufio.NewScanner(strings.NewReader(s))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if idx := strings.Index(line, "|"); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		start := 0
		// skip leading offset if present
		if len(fields) > 1 && isHexToken(fields[0]) && (len(fields[0]) >= 4 || strings.HasSuffix(fields[0], ":")) {
			start = 1
		}
		for _, tok := range fields[start:] {
			tok = strings.TrimSuffix(tok, ":")
			if !isHexToken(tok) {
				continue
			}
			if len(tok)%2 != 0 {
				// single-byte tokens like "0a" are fine; odd longer tokens error
				if len(tok) == 1 {
					tok = "0" + tok
				} else {
					return nil, &HexError{Line: lineNo, Msg: "odd hex token in dump", Snippet: tok}
				}
			}
			b, err := ParseHex(tok)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, &HexError{Msg: "no hex bytes in dump"}
	}
	return out, nil
}

// ParseAuto tries hex dump, then flexible hex string.
func ParseAuto(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, &HexError{Msg: "empty input"}
	}
	if LooksLikeHexDump(s) {
		if b, err := ParseHexDump(s); err == nil {
			return b, nil
		}
	}
	return ParseHex(s)
}

// LoadOptions controls ingestion.
type LoadOptions struct {
	MaxRecordBytes   int        // 0 = unlimited
	MaxMessages      int        // 0 = unlimited; truncation recorded in Dataset.Meta
	Binary           bool       // treat files as raw binary
	OnePerLine       bool       // each non-empty line is a hex message
	CapturedOverride *time.Time // if set, applied to all loaded messages
}

// LoadPath loads a file or directory into a dataset.
func LoadPath(path string, opts LoadOptions) (*wt.Dataset, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	ds := wt.NewDataset(filepath.Base(path))
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
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
			if opts.MaxMessages > 0 && ds.Len() >= opts.MaxMessages {
				markTruncated(ds, "max_messages", ds.Len())
				break
			}
			fp := filepath.Join(path, name)
			before := ds.Len()
			if err := loadFileInto(ds, fp, opts); err != nil {
				return nil, fmt.Errorf("%s: %w", fp, err)
			}
			if opts.MaxMessages > 0 && ds.Len() > opts.MaxMessages {
				ds.Messages = ds.Messages[:opts.MaxMessages]
				markTruncated(ds, "max_messages", ds.Len())
				_ = before
				break
			}
		}
		return ds, nil
	}
	if err := loadFileInto(ds, path, opts); err != nil {
		return nil, err
	}
	if opts.MaxMessages > 0 && ds.Len() > opts.MaxMessages {
		ds.Messages = ds.Messages[:opts.MaxMessages]
		markTruncated(ds, "max_messages", ds.Len())
	}
	return ds, nil
}

func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

func captureTime(opts LoadOptions, base time.Time, seq int) *time.Time {
	if opts.CapturedOverride != nil {
		t := opts.CapturedOverride.UTC()
		return &t
	}
	if base.IsZero() {
		return nil
	}
	t := base.Add(time.Duration(seq) * time.Millisecond)
	return &t
}

func loadFileInto(ds *wt.Dataset, path string, opts LoadOptions) error {
	// PCAP / PCAPNG — analysis ingest only (not acquisition).
	lowerPath := strings.ToLower(path)
	if strings.HasSuffix(lowerPath, ".pcap") || strings.HasSuffix(lowerPath, ".pcapng") {
		part, err := ImportPCAP(path, opts)
		if err != nil {
			return err
		}
		for _, m := range part.Messages {
			if opts.MaxMessages > 0 && ds.Len() >= opts.MaxMessages {
				markTruncated(ds, "max_messages", ds.Len())
				return nil
			}
			if err := ds.Add(m); err != nil {
				return err
			}
		}
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	mtime := fileModTime(path)
	ext := strings.ToLower(filepath.Ext(path))
	name := filepath.Base(path)

	if opts.Binary || ext == ".bin" || ext == ".raw" || isMostlyBinary(data) {
		payload := data
		truncated := false
		if opts.MaxRecordBytes > 0 && len(payload) > opts.MaxRecordBytes {
			payload = payload[:opts.MaxRecordBytes]
			truncated = true
		}
		return ds.Add(&wt.Message{
			ID:        "file_" + hashID(data),
			Data:      append([]byte(nil), payload...),
			Source:    wt.Source{Kind: "file", Path: path},
			Truncated: truncated,
			Captured:  captureTime(opts, mtime, 0),
			Metadata:  map[string]string{"filename": name},
		})
	}

	text := string(data)
	if opts.OnePerLine || strings.Count(text, "\n") > 0 && looksLikeHexLines(text) {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 16*1024*1024)
		lineNo := 0
		seq := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if opts.MaxMessages > 0 && ds.Len() >= opts.MaxMessages {
				markTruncated(ds, "max_messages", ds.Len())
				return nil
			}
			b, err := ParseAuto(line)
			if err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
			truncated := false
			if opts.MaxRecordBytes > 0 && len(b) > opts.MaxRecordBytes {
				b = b[:opts.MaxRecordBytes]
				truncated = true
			}
			if err := ds.Add(&wt.Message{
				ID:        fmt.Sprintf("%s_L%d_%s", name, lineNo, hashID(b)),
				Data:      b,
				Source:    wt.Source{Kind: "file", Path: path, Line: lineNo},
				Truncated: truncated,
				Captured:  captureTime(opts, mtime, seq),
			}); err != nil {
				return err
			}
			seq++
		}
		return scanner.Err()
	}

	b, err := ParseAuto(text)
	if err != nil {
		payload := data
		truncated := false
		if opts.MaxRecordBytes > 0 && len(payload) > opts.MaxRecordBytes {
			payload = payload[:opts.MaxRecordBytes]
			truncated = true
		}
		return ds.Add(&wt.Message{
			ID:        "file_" + hashID(data),
			Data:      append([]byte(nil), payload...),
			Source:    wt.Source{Kind: "file", Path: path},
			Truncated: truncated,
			Captured:  captureTime(opts, mtime, 0),
		})
	}
	truncated := false
	if opts.MaxRecordBytes > 0 && len(b) > opts.MaxRecordBytes {
		b = b[:opts.MaxRecordBytes]
		truncated = true
	}
	return ds.Add(&wt.Message{
		ID:        "file_" + hashID(b),
		Data:      b,
		Source:    wt.Source{Kind: "hex", Path: path},
		Truncated: truncated,
		Captured:  captureTime(opts, mtime, 0),
	})
}

func looksLikeHexLines(text string) bool {
	lines := 0
	hexish := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines++
		if _, err := ParseHex(line); err == nil {
			hexish++
		}
	}
	return lines > 0 && hexish*2 >= lines
}

func isMostlyBinary(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	nonPrint := 0
	n := len(data)
	if n > 512 {
		n = 512
	}
	for i := 0; i < n; i++ {
		c := data[i]
		if c == 0 || c > 127 || (c < 32 && c != '\n' && c != '\r' && c != '\t') {
			nonPrint++
		}
	}
	return nonPrint*4 >= n
}

func hashID(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:8])
}

// LoadReader loads hex or binary from a reader (e.g. stdin).
func LoadReader(r io.Reader, name string, opts LoadOptions) (*wt.Dataset, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	ds := wt.NewDataset(name)
	text := string(data)
	if opts.OnePerLine || looksLikeHexLines(text) {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 16*1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			b, err := ParseAuto(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			_ = ds.Add(&wt.Message{
				ID:     fmt.Sprintf("stdin_L%d_%s", lineNo, hashID(b)),
				Data:   b,
				Source: wt.Source{Kind: "stdin", Line: lineNo},
			})
		}
		return ds, scanner.Err()
	}
	if opts.Binary || isMostlyBinary(data) {
		_ = ds.Add(&wt.Message{
			ID:     "stdin_" + hashID(data),
			Data:   append([]byte(nil), data...),
			Source: wt.Source{Kind: "stdin"},
		})
		return ds, nil
	}
	b, err := ParseAuto(text)
	if err != nil {
		return nil, err
	}
	_ = ds.Add(&wt.Message{
		ID:     "stdin_" + hashID(b),
		Data:   b,
		Source: wt.Source{Kind: "stdin"},
	})
	return ds, nil
}

// LoadHexStrings creates a dataset from hex strings.
func LoadHexStrings(hexes []string, sourceKind string) (*wt.Dataset, error) {
	ds := wt.NewDataset("hex")
	for i, h := range hexes {
		b, err := ParseAuto(h)
		if err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
		if err := ds.Add(&wt.Message{
			ID:     fmt.Sprintf("hex_%d_%s", i, hashID(b)),
			Data:   b,
			Source: wt.Source{Kind: sourceKind},
		}); err != nil {
			return nil, err
		}
	}
	return ds, nil
}
