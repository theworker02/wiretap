package compare_test

import (
	"strconv"
	"testing"

	"github.com/theworker02/wiretap/internal/compare"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestDiffAndCorrelate(t *testing.T) {
	ds := wt.NewDataset("diff")
	for i := 0; i < 6; i++ {
		typ := "1"
		if i >= 3 {
			typ = "2"
		}
		msg := []byte{0xAA, byte(i), byte(typ[0] - '0')}
		_ = ds.Add(&wt.Message{
			ID:   strconv.Itoa(i),
			Data: msg,
			Labels: map[string]string{
				"type": typ,
				"seq":  strconv.Itoa(i),
			},
		})
	}
	d, err := compare.Diff(ds, "type", "1", "2")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changed) == 0 {
		t.Fatal("expected changed regions")
	}
	corr, err := compare.CorrelateNumeric(ds, "seq", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range corr {
		if c.Offset == 1 && (c.Method == "exact" || c.Method == "pearson" || c.Method == "transform") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected correlation for seq at offset 1: %+v", corr)
	}
}
