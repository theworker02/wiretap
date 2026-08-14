package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/theworker02/wiretap/internal/report"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestWriteHTML(t *testing.T) {
	res := &wt.Result{
		SchemaVersion:      wt.ReportVersion,
		Budget:             "quick",
		MessageCount:       1,
		DatasetFingerprint: "abc",
		ConfigFingerprint:  "def",
		Hypotheses: []wt.Hypothesis{
			{ID: "len", Kind: "length", Offset: 4, Length: 2, Description: "length field",
				Confidence: wt.Confidence{Level: wt.ConfidenceHigh, Score: 1}},
		},
		Stats: []wt.ByteStat{{Offset: 0, Entropy: 1.5}, {Offset: 1, Entropy: 7.2}},
	}
	ds := &wt.Dataset{Messages: []*wt.Message{{ID: "m0", Data: []byte{0x01, 0x02, 0x03, 0x04}}}}
	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, res, ds); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{"<!DOCTYPE html>", "Hypotheses", "Entropy", "length", "<svg"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in html", want)
		}
	}
}
