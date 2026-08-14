package wiretap

import "io"

// IngestOptions configures public load helpers.
type IngestOptions struct {
	Binary         bool
	OnePerLine     bool
	MaxRecordBytes int
	MaxMessages    int // 0 = unlimited; truncation recorded in Dataset.Meta
}

// ingestFuncs are registered by internal/capture via RegisterIngest.
var ingestFuncs struct {
	parseHex   func(string) ([]byte, error)
	loadHex    func([]string) (*Dataset, error)
	loadFile   func(string, IngestOptions) (*Dataset, error)
	loadDir    func(string, IngestOptions) (*Dataset, error)
	loadPath   func(string, IngestOptions) (*Dataset, error)
	loadReader func(r io.Reader, name string, opts IngestOptions) (*Dataset, error)
}

// RegisterIngest wires capture backends into the public API (called from capture init).
func RegisterIngest(
	parseHex func(string) ([]byte, error),
	loadHex func([]string) (*Dataset, error),
	loadFile func(string, IngestOptions) (*Dataset, error),
	loadDir func(string, IngestOptions) (*Dataset, error),
	loadPath func(string, IngestOptions) (*Dataset, error),
	loadReader func(r io.Reader, name string, opts IngestOptions) (*Dataset, error),
) {
	ingestFuncs.parseHex = parseHex
	ingestFuncs.loadHex = loadHex
	ingestFuncs.loadFile = loadFile
	ingestFuncs.loadDir = loadDir
	ingestFuncs.loadPath = loadPath
	ingestFuncs.loadReader = loadReader
}

func requireIngest() error {
	if ingestFuncs.parseHex == nil {
		return ErrNotRegistered
	}
	return nil
}

// ParseHex decodes flexible hex (spaces, 0x, colons) into bytes.
func ParseHex(s string) ([]byte, error) {
	if err := requireIngest(); err != nil {
		return nil, err
	}
	return ingestFuncs.parseHex(s)
}

// LoadHex builds a dataset from hex strings (one message each).
func LoadHex(hexes []string) (*Dataset, error) {
	if err := requireIngest(); err != nil {
		return nil, err
	}
	return ingestFuncs.loadHex(hexes)
}

// LoadFile loads a single capture file.
func LoadFile(path string) (*Dataset, error) {
	return LoadFileOpts(path, IngestOptions{OnePerLine: true})
}

// LoadFileOpts loads a file with options.
func LoadFileOpts(path string, opts IngestOptions) (*Dataset, error) {
	if err := requireIngest(); err != nil {
		return nil, err
	}
	return ingestFuncs.loadFile(path, opts)
}

// LoadDir loads all eligible files in a directory.
func LoadDir(path string) (*Dataset, error) {
	return LoadDirOpts(path, IngestOptions{OnePerLine: true})
}

// LoadDirOpts loads a directory with options.
func LoadDirOpts(path string, opts IngestOptions) (*Dataset, error) {
	if err := requireIngest(); err != nil {
		return nil, err
	}
	return ingestFuncs.loadDir(path, opts)
}

// LoadPath loads a file or directory.
func LoadPath(path string, opts IngestOptions) (*Dataset, error) {
	if err := requireIngest(); err != nil {
		return nil, err
	}
	return ingestFuncs.loadPath(path, opts)
}

// LoadReader loads from an io.Reader (e.g. stdin).
func LoadReader(r io.Reader, name string, opts IngestOptions) (*Dataset, error) {
	if err := requireIngest(); err != nil {
		return nil, err
	}
	return ingestFuncs.loadReader(r, name, opts)
}
