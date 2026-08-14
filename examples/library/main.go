package main

// Library usage example — run from repo root:
//
//	go run ./examples/library
//
// Wiretap analyzes authorized captures offline with evidence-backed hypotheses.

import (
	"context"
	"fmt"
	"os"

	_ "github.com/theworker02/wiretap/internal/analysis" // register analyzer
	_ "github.com/theworker02/wiretap/internal/capture"  // register ingest
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func main() {
	path := "examples/mystery/captures.hex"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	ds, err := wt.LoadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{
		Budget: wt.BudgetQuick,
		Progress: func(done, total int, pass string) {
			fmt.Fprintf(os.Stderr, "pass %d/%d %s\n", done, total, pass)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("messages=%d hypotheses=%d fingerprint=%s\n",
		res.MessageCount, len(res.Hypotheses), res.DatasetFingerprint)
	for i, h := range res.Hypotheses {
		if i >= 5 {
			fmt.Printf("… %d more\n", len(res.Hypotheses)-5)
			break
		}
		fmt.Printf("  %-10s %-8s %s\n", h.Kind, h.Confidence.Level, h.ID)
	}
}
