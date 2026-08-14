package wiretap_test

import (
	"testing"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestDatasetSearchFindsNonOverlappingHits(t *testing.T) {
	ds := wt.NewDataset("search")
	if err := ds.Add(&wt.Message{ID: "a", Data: []byte("xxHTTPyyHTTP")}); err != nil {
		t.Fatal(err)
	}
	if err := ds.Add(&wt.Message{ID: "b", Data: []byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01}}); err != nil {
		t.Fatal(err)
	}

	ascii, err := ds.Search([]byte("HTTP"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ascii) != 2 {
		t.Fatalf("ascii hits=%d want 2: %#v", len(ascii), ascii)
	}
	if ascii[0].MessageID != "a" || ascii[0].Offset != 2 || ascii[1].Offset != 8 {
		t.Fatalf("ascii hits=%#v", ascii)
	}

	hexHits, err := ds.Search([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err != nil {
		t.Fatal(err)
	}
	if len(hexHits) != 1 || hexHits[0].MessageIndex != 1 || hexHits[0].Offset != 1 {
		t.Fatalf("hex hits=%#v", hexHits)
	}
	if hexHits[0].ContextHex == "" {
		t.Fatal("expected context hex")
	}
}

func TestDatasetSearchEmptyPattern(t *testing.T) {
	ds := wt.NewDataset("search")
	if _, err := ds.Search(nil); err == nil {
		t.Fatal("expected empty pattern error")
	}
}

func TestDatasetSearchNoHits(t *testing.T) {
	ds := wt.NewDataset("search")
	if err := ds.Add(&wt.Message{ID: "a", Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	hits, err := ds.Search([]byte("zzz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("hits=%#v", hits)
	}
}
