package project_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/theworker02/wiretap/internal/project"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestProjectLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := project.Init(dir, "demo"); err != nil {
		t.Fatal(err)
	}
	if err := project.Init(dir, "demo"); err == nil {
		t.Fatal("expected ErrProjectExists")
	}
	root, err := project.FindRoot(filepath.Join(dir, "samples"))
	if err != nil || root != dir {
		t.Fatalf("FindRoot: %v %q", err, root)
	}
	path, err := project.AddSampleHex(dir, "a.hex", "deadbeef", map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	ds, err := project.LoadSamples(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 1 || ds.Messages[0].Labels["k"] != "v" {
		t.Fatalf("%+v", ds)
	}
	annPath, err := project.Annotate(dir, project.Annotation{Offset: 0, Length: 2, Kind: "magic", Label: "MAGIC"})
	if err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(annPath)
	id = id[:len(id)-len(".yaml")]
	if _, err := project.Annotate(dir, project.Annotation{ID: id, Offset: 0, Length: 1}); err == nil {
		t.Fatal("should refuse overwrite")
	}
	list, err := project.ListAnnotations(dir)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %#v", err, list)
	}
	if err := project.Unannotate(dir, id); err != nil {
		t.Fatal(err)
	}
	if err := project.Unannotate(dir, id); err == nil {
		t.Fatal("expected not found")
	}
	_ = wt.ErrNotFound
}

func TestSampleListRemoveLabelTree(t *testing.T) {
	dir := t.TempDir()
	if err := project.Init(dir, "cli"); err != nil {
		t.Fatal(err)
	}
	if _, err := project.AddSampleHex(dir, "b.hex", "01020304", map[string]string{"mode": "idle"}); err != nil {
		t.Fatal(err)
	}
	items, err := project.ListSamples(dir)
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %v %#v", err, items)
	}
	if items[0].Labels["mode"] != "idle" {
		t.Fatalf("labels: %#v", items[0].Labels)
	}
	if err := project.SetSampleLabels(dir, "b.hex", map[string]string{"temp": "20"}); err != nil {
		t.Fatal(err)
	}
	items, _ = project.ListSamples(dir)
	if items[0].Labels["temp"] != "20" || items[0].Labels["mode"] != "idle" {
		t.Fatalf("merged labels: %#v", items[0].Labels)
	}
	tree, err := project.Tree(dir)
	if err != nil || tree["samples"] != 1 || tree["notes"] != 0 {
		t.Fatalf("tree: %v %#v", err, tree)
	}
	if err := project.RemoveSample(dir, "b.hex"); err != nil {
		t.Fatal(err)
	}
	items, _ = project.ListSamples(dir)
	if len(items) != 0 {
		t.Fatalf("expected empty after rm, got %#v", items)
	}
}
