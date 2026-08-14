package inference_test

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/theworker02/wiretap/internal/inference"
	"github.com/theworker02/wiretap/internal/project"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestArrayPassDetectsCountRecords(t *testing.T) {
	ds := wt.NewDataset("arr")
	for i, n := range []int{2, 3, 4} {
		b := []byte{0xAA, 0xBB, byte(n)}
		for e := 0; e < n; e++ {
			var eb [4]byte
			binary.BigEndian.PutUint32(eb[:], uint32(e+1))
			b = append(b, eb[:]...)
		}
		_ = ds.Add(&wt.Message{ID: string(rune('a' + i)), Data: b})
	}
	out, err := (inference.ArrayPass{}).Run(context.Background(), &wt.PassInput{
		Dataset: ds, Budget: wt.BudgetNormal, Config: wt.DefaultPassConfig(wt.BudgetNormal),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range out.Hypotheses {
		if h.Kind == "array" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected array hyp, got %#v", out.Hypotheses)
	}
}

func TestAnnotationBoostAndWarn(t *testing.T) {
	h := wt.Hypothesis{
		ID: "len_o4", Kind: "length", Offset: 4, Length: 2,
		Confidence: wt.DeriveConfidence([]wt.EvidenceItem{
			{Kind: "support", Description: "strong", Weight: 4},
			{Kind: "support", Description: "match", Weight: 2},
		}),
	}
	pass := inference.AnnotationPass{Annotations: []project.Annotation{
		{ID: "a1", Offset: 4, Length: 2, Kind: "length", Label: "msg_len"},
		{ID: "a2", Offset: 4, Length: 2, Kind: "checksum", Label: "wrong"},
	}}
	out, err := pass.Run(context.Background(), &wt.PassInput{
		Hypotheses: []wt.Hypothesis{h},
		Config:     wt.DefaultPassConfig(wt.BudgetNormal),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Hypotheses) == 0 {
		t.Fatal("expected boosted hyp")
	}
	res := &wt.Result{Observations: out.Observations}
	inference.ApplyAnnotationWarnings(res)
	if len(res.Warnings) == 0 {
		// conflict observation should exist
		found := false
		for _, o := range out.Observations {
			if o.Kind == "annotation_conflict" {
				found = true
			}
		}
		if !found {
			t.Fatal("expected annotation conflict observation")
		}
	}
}

func TestLengthPrefixedU16(t *testing.T) {
	ds := wt.NewDataset("s")
	for i, s := range []string{"hello", "world!", "abcdef"} {
		b := make([]byte, 2+len(s))
		binary.BigEndian.PutUint16(b[0:2], uint16(len(s)))
		copy(b[2:], s)
		_ = ds.Add(&wt.Message{ID: string(rune('a' + i)), Data: b})
	}
	out, err := (inference.StringPass{}).Run(context.Background(), &wt.PassInput{
		Dataset: ds, Budget: wt.BudgetNormal, Config: wt.DefaultPassConfig(wt.BudgetNormal),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range out.Hypotheses {
		if enc, _ := h.Params["encoding"].(string); enc == "lenpref-u16-be" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected u16-be length-prefixed string: %#v", out.Hypotheses)
	}
}
