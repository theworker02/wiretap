package capture_test

import (
	"testing"

	"github.com/theworker02/wiretap/internal/capture"
)

func TestParseHexTable(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []byte
		wantErr bool
	}{
		{"plain", "deadbeef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"spaces", "de ad be ef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"colons", "de:ad:be:ef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"0x", "0xdeadbeef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"mixed", "0xde ad:be-ef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"odd", "abc", nil, true},
		{"bad", "zz", nil, true},
		{"empty", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := capture.ParseHex(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("got %x want %x", got, tt.want)
			}
		})
	}
}

func TestParseHexDump(t *testing.T) {
	dump := `0000  be 71 01 01 00 13 00 64  66 5b 7a 00 01 70 69 6e  |.q.....df[z..pin|
0010  67 ab cd                                       |g..|
`
	b, err := capture.ParseHexDump(dump)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 16 {
		t.Fatalf("too short: %d", len(b))
	}
	if b[0] != 0xbe || b[1] != 0x71 {
		t.Fatalf("unexpected start %x", b[:2])
	}
}

func FuzzParseHex(f *testing.F) {
	f.Add("deadbeef")
	f.Add("de:ad:be:ef")
	f.Add("0x00")
	f.Add("")
	f.Add("zzz")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = capture.ParseHex(s) // must not panic
		_, _ = capture.ParseAuto(s)
	})
}
