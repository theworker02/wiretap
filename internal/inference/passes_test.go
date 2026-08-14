package inference_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/theworker02/wiretap/internal/inference"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func crc16CCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func TestChecksumTrailerDiscovery(t *testing.T) {
	ds := wt.NewDataset("csum")
	for i := 0; i < 8; i++ {
		payload := []byte{0xAA, 0xBB, byte(i), byte(i + 1), byte(i + 2)}
		sum := crc16CCITT(payload)
		msg := append(append([]byte{}, payload...), byte(sum>>8), byte(sum))
		if err := ds.Add(&wt.Message{ID: fmt.Sprintf("m%d", i), Data: msg}); err != nil {
			t.Fatal(err)
		}
	}
	pass := &inference.ChecksumPass{}
	out, err := pass.Run(context.Background(), &wt.PassInput{
		Dataset: ds,
		Budget:  wt.BudgetNormal,
		Config:  wt.DefaultPassConfig(wt.BudgetNormal),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range out.Hypotheses {
		if h.Kind == "checksum" {
			if alg, _ := h.Params["alg"].(string); alg == "crc16-ccitt" {
				found = true
				if h.Confidence.Level == wt.ConfidenceUnknown || h.Confidence.Level == wt.ConfidenceInsufficient {
					t.Fatalf("expected real confidence, got %s", h.Confidence.Level)
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected crc16-ccitt hypothesis, got %+v", out.Hypotheses)
	}
}

func TestLengthField(t *testing.T) {
	ds := wt.NewDataset("len")
	for i := 0; i < 6; i++ {
		payload := make([]byte, 4+i)
		for j := range payload {
			payload[j] = byte(j)
		}
		msg := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(msg[0:2], uint16(len(msg)))
		copy(msg[2:], payload)
		_ = ds.Add(&wt.Message{ID: fmt.Sprintf("m%d", i), Data: msg})
	}
	out, err := inference.LengthFieldPass{}.Run(context.Background(), &wt.PassInput{
		Dataset: ds, Budget: wt.BudgetNormal, Config: wt.DefaultPassConfig(wt.BudgetNormal),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range out.Hypotheses {
		if h.Kind == "length" && h.Offset == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected length field at 0, got %#v", out.Hypotheses)
	}
}

func TestCounter(t *testing.T) {
	ds := wt.NewDataset("ctr")
	for i := 0; i < 10; i++ {
		msg := []byte{0x01, byte(i), 0xFF}
		_ = ds.Add(&wt.Message{ID: fmt.Sprintf("m%d", i), Data: msg})
	}
	out, err := inference.CounterPass{}.Run(context.Background(), &wt.PassInput{
		Dataset: ds, Budget: wt.BudgetNormal, Config: wt.DefaultPassConfig(wt.BudgetNormal),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range out.Hypotheses {
		if h.Kind == "counter" && h.Offset == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected counter at offset 1")
	}
}

func FuzzChecksum(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = inference.ComputeChecksum(inference.AlgXOR8, data)
		_ = inference.ComputeChecksum(inference.AlgCRC16CCITT, data)
		_ = inference.ComputeChecksum(inference.AlgCRC32IEEE, data)
	})
}
