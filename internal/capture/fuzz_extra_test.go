package capture_test

import (
	"encoding/hex"
	"testing"

	"github.com/theworker02/wiretap/internal/capture"
)

func TestParseHexRoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 'A', 'Z'}
	s := hex.EncodeToString(raw)
	got, err := capture.ParseHex(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("%x != %x", got, raw)
	}
	// spaced form
	spaced := "00 01 7f 80 fe ff 41 5a"
	got2, err := capture.ParseHex(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != string(raw) {
		t.Fatalf("spaced %x", got2)
	}
}

func FuzzPCAPNG(f *testing.F) {
	f.Add([]byte{0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		_, _ = capture.ParsePCAPNGForFuzz(data)
	})
}
