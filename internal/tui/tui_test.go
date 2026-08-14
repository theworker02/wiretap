package tui_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/theworker02/wiretap/internal/tui"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestBrowseReportPlainFallback(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	res := &wt.Result{
		DatasetName: "t", MessageCount: 1, MinLength: 4, MaxLength: 4,
		Budget: "quick", Hypotheses: []wt.Hypothesis{
			{ID: "h1", Kind: "length", Offset: 0, Length: 2,
				Confidence:  wt.Confidence{Level: wt.ConfidenceHigh, Score: 1},
				Description: "test"},
		},
	}
	in := strings.NewReader("3\nq\n")
	var out bytes.Buffer
	if err := tui.BrowseReport(&out, in, res, nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "Wiretap TUI") {
		t.Fatalf("missing header: %s", s)
	}
	if !strings.Contains(s, "h1") {
		t.Fatalf("missing hyp: %s", s)
	}
}
