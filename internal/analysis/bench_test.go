package analysis_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/theworker02/wiretap/internal/analysis"
	"github.com/theworker02/wiretap/internal/capture"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func loadBench(b *testing.B, name string) *wt.Dataset {
	b.Helper()
	root := filepath.Join("..", "..", "testdata", "bench", name, "captures.hex")
	if _, err := os.Stat(root); err != nil {
		b.Skip("bench dataset missing; run: go run ./scripts/gen_bench.go")
	}
	ds, err := capture.LoadPath(root, capture.LoadOptions{OnePerLine: true})
	if err != nil {
		b.Fatal(err)
	}
	return ds
}

func BenchmarkAnalyzeTiny(b *testing.B) {
	ds := loadBench(b, "tiny_fixed")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analysis.NewPipeline(analysis.Options{Budget: wt.BudgetQuick}).Run(context.Background(), ds)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeVariable(b *testing.B) {
	ds := loadBench(b, "variable_payload")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analysis.NewPipeline(analysis.Options{Budget: wt.BudgetQuick}).Run(context.Background(), ds)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeChecksumHeavy(b *testing.B) {
	ds := loadBench(b, "checksum_heavy")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analysis.NewPipeline(analysis.Options{Budget: wt.BudgetQuick}).Run(context.Background(), ds)
		if err != nil {
			b.Fatal(err)
		}
	}
}
