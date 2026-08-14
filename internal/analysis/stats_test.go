package analysis_test

import (
	"context"
	"testing"

	"github.com/theworker02/wiretap/internal/analysis"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestByteStatsAndConstants(t *testing.T) {
	ds := wt.NewDataset("t")
	for i := 0; i < 5; i++ {
		_ = ds.Add(&wt.Message{ID: string(rune('a' + i)), Data: []byte{0xBE, 0x71, byte(i), 0x00}})
	}
	stats := analysis.ComputeByteStats(ds)
	if len(stats) != 4 {
		t.Fatalf("stats len %d", len(stats))
	}
	if stats[0].Unique != 1 || stats[0].Mode != 0xBE {
		t.Fatalf("offset0 %#v", stats[0])
	}
	if stats[0].Entropy != 0 {
		t.Fatalf("const entropy want 0 got %f", stats[0].Entropy)
	}
	consts := analysis.DetectConstants(stats)
	if len(consts) == 0 {
		t.Fatal("expected constants")
	}
}

func TestPipelineDeterministic(t *testing.T) {
	ds := wt.NewDataset("d")
	for i := 0; i < 8; i++ {
		msg := []byte{0xAA, 0xBB, byte(i), byte(10 + i)}
		_ = ds.Add(&wt.Message{ID: string(rune('a' + i)), Data: msg})
	}
	p := analysis.NewPipeline(analysis.Options{Budget: wt.BudgetQuick})
	r1, err := p.Run(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := p.Run(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	if r1.DatasetFingerprint != r2.DatasetFingerprint {
		t.Fatal("fingerprint mismatch")
	}
	if r1.ConfigFingerprint != r2.ConfigFingerprint {
		t.Fatal("config fingerprint mismatch")
	}
	if len(r1.Hypotheses) != len(r2.Hypotheses) {
		t.Fatalf("hypothesis count %d vs %d", len(r1.Hypotheses), len(r2.Hypotheses))
	}
	for i := range r1.Hypotheses {
		if r1.Hypotheses[i].ID != r2.Hypotheses[i].ID {
			t.Fatalf("order/id mismatch at %d", i)
		}
	}
}

func TestEmptyDataset(t *testing.T) {
	p := analysis.NewPipeline(analysis.Options{})
	_, err := p.Run(context.Background(), wt.NewDataset("x"))
	if err != wt.ErrEmptyDataset {
		t.Fatalf("got %v", err)
	}
}

func BenchmarkByteStats(b *testing.B) {
	ds := wt.NewDataset("b")
	for i := 0; i < 100; i++ {
		data := make([]byte, 64)
		for j := range data {
			data[j] = byte(i + j)
		}
		_ = ds.Add(&wt.Message{ID: string(rune(i)), Data: data})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analysis.ComputeByteStats(ds)
	}
}
