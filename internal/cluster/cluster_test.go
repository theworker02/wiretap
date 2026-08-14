package cluster_test

import (
	"fmt"
	"testing"

	"github.com/theworker02/wiretap/internal/cluster"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestClusterByTypeByte(t *testing.T) {
	ds := wt.NewDataset("c")
	for i := 0; i < 9; i++ {
		typ := byte(1 + i%3)
		msg := []byte{0xAA, 0xBB, typ, byte(i), 0x00, 0x00}
		_ = ds.Add(&wt.Message{ID: fmt.Sprintf("m%d", i), Data: msg})
	}
	// Prefix includes type byte; disable further similarity splitting.
	res, err := cluster.ClusterMessages(ds, cluster.Options{PrefixLen: 3, SimilarityMin: 0.0, MinClusterSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Clusters) != 3 {
		t.Fatalf("expected 3 clusters by type prefix, got %d (%+v)", len(res.Clusters), res.Clusters)
	}
	foundType := false
	for _, tf := range res.TypeFields {
		if tf.Offset == 2 {
			foundType = true
		}
	}
	if !foundType {
		t.Fatalf("expected type field at offset 2, got %+v", res.TypeFields)
	}
}
