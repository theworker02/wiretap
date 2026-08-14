package tui

import (
	"bufio"
	"io"
	"os"

	"golang.org/x/term"
)

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

type lineScanner struct {
	sc  *bufio.Scanner
	err error
}

func newLineScanner(r io.Reader) *lineScanner {
	return &lineScanner{sc: bufio.NewScanner(r)}
}

func (s *lineScanner) Scan() (string, bool) {
	if !s.sc.Scan() {
		s.err = s.sc.Err()
		return "", false
	}
	return s.sc.Text(), true
}

func (s *lineScanner) Err() error { return s.err }
