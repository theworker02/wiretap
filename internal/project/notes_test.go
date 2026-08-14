package project_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/theworker02/wiretap/internal/project"
)

func TestNotesAddListSearch(t *testing.T) {
	dir := t.TempDir()
	if err := project.Init(dir, "notes-demo"); err != nil {
		t.Fatal(err)
	}
	off := 4
	if _, _, err := project.AddNote(dir, &off, "device id?"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.AddNote(dir, nil, "freeform observation"); err != nil {
		t.Fatal(err)
	}
	all, err := project.ListNotes(dir)
	if err != nil || len(all) != 2 {
		t.Fatalf("list=%d err=%v", len(all), err)
	}
	hit, err := project.SearchNotes(dir, "device")
	if err != nil || len(hit) != 1 {
		t.Fatalf("search=%d err=%v", len(hit), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes")); err != nil {
		t.Fatal(err)
	}
}
