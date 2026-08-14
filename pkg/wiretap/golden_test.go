package wiretap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	_ "github.com/theworker02/wiretap/internal/analysis"
	_ "github.com/theworker02/wiretap/internal/capture"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// TestAnalyzeMysteryGolden compares stable fields of analyze --format json on the
// mystery corpus. Timestamps / elapsed / tool commit are normalized away.
func TestAnalyzeMysteryGolden(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	hexPath := filepath.Join(root, "examples", "mystery", "captures.hex")
	if _, err := os.Stat(hexPath); err != nil {
		t.Skip("mystery captures missing")
	}
	ds, err := wt.LoadFile(hexPath)
	if err != nil {
		t.Fatal(err)
	}
	res, err := wt.Analyze(context.Background(), ds, wt.AnalyzeOptions{Budget: wt.BudgetQuick})
	if err != nil {
		t.Fatal(err)
	}
	got := normalizeReport(res)
	goldenPath := filepath.Join(root, "testdata", "golden", "mystery_analyze_quick.json")
	if os.Getenv("WIRETAP_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(goldenPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated golden %s", goldenPath)
		return
	}
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (set WIRETAP_UPDATE_GOLDEN=1 to create): %v", err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	gotRaw, _ := json.Marshal(got)
	wantRaw, _ := json.Marshal(want)
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatalf("golden mismatch\n got: %s\nwant: %s", gotRaw, wantRaw)
	}
}

func normalizeReport(res *wt.Result) map[string]any {
	ids := make([]string, 0, len(res.Hypotheses))
	kinds := map[string]int{}
	for _, h := range res.Hypotheses {
		ids = append(ids, h.ID)
		kinds[h.Kind]++
	}
	sort.Strings(ids)
	kindKeys := make([]string, 0, len(kinds))
	for k := range kinds {
		kindKeys = append(kindKeys, k)
	}
	sort.Strings(kindKeys)
	kindCounts := map[string]int{}
	for _, k := range kindKeys {
		kindCounts[k] = kinds[k]
	}
	return map[string]any{
		"schema_version":      res.SchemaVersion,
		"budget":              res.Budget,
		"message_count":       res.MessageCount,
		"min_length":          res.MinLength,
		"max_length":          res.MaxLength,
		"dataset_fingerprint": res.DatasetFingerprint,
		"config_fingerprint":  res.ConfigFingerprint,
		"hypothesis_count":    len(res.Hypotheses),
		"hypothesis_ids":      ids,
		"kind_counts":         kindCounts,
	}
}
