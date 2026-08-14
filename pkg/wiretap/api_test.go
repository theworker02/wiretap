package wiretap_test

import (
	"context"
	"testing"

	_ "github.com/theworker02/wiretap/internal/analysis" // register analyzer backend
	_ "github.com/theworker02/wiretap/internal/capture"  // register ingest backend
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestPublicAPI(t *testing.T) {
	ds := wt.NewDataset("api")
	for i := 0; i < 5; i++ {
		if err := ds.Add(&wt.Message{Data: []byte{0x01, 0x02, byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{Budget: wt.BudgetQuick})
	if err != nil {
		t.Fatal(err)
	}
	if res.SchemaVersion != wt.ReportVersion {
		t.Fatalf("schema version %s", res.SchemaVersion)
	}
	if res.DatasetFingerprint == "" {
		t.Fatal("missing fingerprint")
	}
	conf := wt.DeriveConfidence(nil)
	if conf.Level != wt.ConfidenceUnknown {
		t.Fatalf("empty evidence should be Unknown, got %s", conf.Level)
	}
}

func TestPublicIngest(t *testing.T) {
	b, err := wt.ParseHex("de ad be ef")
	if err != nil || len(b) != 4 {
		t.Fatalf("%v %x", err, b)
	}
	ds, err := wt.LoadHex([]string{"0102", "0304"})
	if err != nil || ds.Len() != 2 {
		t.Fatalf("%v %v", err, ds)
	}
}
