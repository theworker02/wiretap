package eval_test

import (
	"context"
	"testing"

	_ "github.com/theworker02/wiretap/internal/analysis"
	_ "github.com/theworker02/wiretap/internal/capture"
	"github.com/theworker02/wiretap/internal/eval"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestEvalSmoke(t *testing.T) {
	ds, truth, err := eval.Generate(eval.ProtocolSpec{
		Seed: 42, Count: 8, WithArray: true, WithString: true, WithCRC: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := eval.Evaluate(context.Background(), ds, truth, wt.BudgetQuick)
	if err != nil {
		t.Fatal(err)
	}
	if m.Messages != 8 {
		t.Fatalf("messages=%d", m.Messages)
	}
	if m.RuntimeMS < 0 {
		t.Fatal("runtime")
	}
	if m.BoundaryRecall <= 0 && m.Hypotheses == 0 {
		t.Fatal("expected some hypotheses or recall on synthetic corpus")
	}
}

// TestEvalRegressionFloor guards fixed-seed normal-budget detection floors.
// Numbers are measured, not claimed production accuracy.
func TestEvalRegressionFloor(t *testing.T) {
	ds, truth, err := eval.Generate(eval.ProtocolSpec{
		Seed: 1, Count: 50, WithArray: true, WithString: true, WithCRC: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := eval.Evaluate(context.Background(), ds, truth, wt.BudgetNormal)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("measured: precision=%.3f recall=%.3f fpr=%.3f length=%.3f checksum=%.3f hyps=%d preds=%d",
		m.BoundaryPrecision, m.BoundaryRecall, m.FalsePositiveRate,
		m.LengthAccuracy, m.ChecksumAccuracy, m.Hypotheses, m.PredictedBoundaries)
	if m.LengthAccuracy < 0.5 && m.ChecksumAccuracy < 0.5 {
		t.Fatalf("eval collapsed: length=%.3f checksum=%.3f (want either >= 0.5)", m.LengthAccuracy, m.ChecksumAccuracy)
	}
	if m.BoundaryRecall < 0.8 {
		t.Fatalf("boundary recall too low: %.3f (want >= 0.8)", m.BoundaryRecall)
	}
	if m.BoundaryPrecision < 0.6 {
		t.Fatalf("boundary precision too low: %.3f (want >= 0.6 under High-primary scoring)", m.BoundaryPrecision)
	}
	if m.FalsePositiveRate > 0.4 {
		t.Fatalf("false positive rate too high: %.3f (want <= 0.4)", m.FalsePositiveRate)
	}
}
