package index

import (
	"path/filepath"
	"testing"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestBuildDiffIncremental(t *testing.T) {
	ds := wt.NewDataset("t")
	_ = ds.Add(&wt.Message{ID: "a", Data: []byte{1, 2, 3}, Source: wt.Source{Path: "a.bin"}})
	_ = ds.Add(&wt.Message{ID: "b", Data: []byte{4, 5}, Source: wt.Source{Path: "b.bin"}})
	idx1 := Build(ds)
	dir := t.TempDir()
	path := filepath.Join(dir, "index.json")
	if err := Save(idx1, path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !NeedsAnalyze(nil, loaded) {
		t.Fatal("expected needs analyze vs nil")
	}
	if NeedsAnalyze(loaded, idx1) {
		t.Fatal("identical should not need analyze")
	}
	ds2 := wt.NewDataset("t")
	_ = ds2.Add(&wt.Message{ID: "a", Data: []byte{1, 2, 3}, Source: wt.Source{Path: "a.bin"}})
	_ = ds2.Add(&wt.Message{ID: "b", Data: []byte{9, 9}, Source: wt.Source{Path: "b.bin"}})
	_ = ds2.Add(&wt.Message{ID: "c", Data: []byte{7}, Source: wt.Source{Path: "c.bin"}})
	idx2 := Build(ds2)
	d := Diff(idx1, idx2)
	if len(d.Changed) != 1 || d.Changed[0].ID != "b" {
		t.Fatalf("changed=%v", d.Changed)
	}
	if len(d.New) != 1 || d.New[0].ID != "c" {
		t.Fatalf("new=%v", d.New)
	}
	if !NeedsAnalyze(idx1, idx2) {
		t.Fatal("expected needs analyze")
	}
}
