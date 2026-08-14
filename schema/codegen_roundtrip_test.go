package schema_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/theworker02/wiretap/schema"
)

// TestGenerateGoCompileRoundTrip writes generated Go into a temp module and runs
// `go test` so Parse* actually compiles and round-trips sample bytes on this OS
// (including Windows).
func TestGenerateGoCompileRoundTrip(t *testing.T) {
	off0, off2, off3, off5 := 0, 2, 3, 5
	s := &schema.Schema{
		Name: "beacon", Version: "0.1.0", Endian: "be",
		Fields: []schema.Field{
			{Name: "magic", Offset: &off0, Length: 2, Type: "bytes", Value: "be71"},
			{Name: "version", Offset: &off2, Length: 1, Type: "u8"},
			{Name: "msg_type", Offset: &off3, Length: 2, Type: "u16", Endian: "be"},
			{Name: "flags", Offset: &off5, Length: 1, Type: "u8"},
		},
	}
	code, err := schema.GenerateGo(s, "beacon")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	mod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(mod, []byte("module wiretap.codegen.roundtrip\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(dir, "beacon")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "beacon_gen.go"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	testSrc := `package beacon_test

import (
	"bytes"
	"testing"

	"wiretap.codegen.roundtrip/beacon"
)

func TestParseRoundTrip(t *testing.T) {
	raw := []byte{0xbe, 0x71, 0x01, 0x12, 0x34, 0x07}
	msg, err := beacon.ParseBeacon(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.Magic, []byte{0xbe, 0x71}) {
		t.Fatalf("magic=%x", msg.Magic)
	}
	if msg.Version != 0x01 {
		t.Fatalf("version=%d", msg.Version)
	}
	if msg.MsgType != 0x1234 {
		t.Fatalf("msg_type=%#x", msg.MsgType)
	}
	if msg.Flags != 0x07 {
		t.Fatalf("flags=%d", msg.Flags)
	}
	if _, err := beacon.ParseBeacon(raw[:3]); err == nil {
		t.Fatal("expected truncate error")
	}
}
`
	if err := os.WriteFile(filepath.Join(pkgDir, "beacon_gen_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "test", "./beacon")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test failed on %s/%s: %v\n%s\n--- generated ---\n%s",
			runtime.GOOS, runtime.GOARCH, err, out, code)
	}
}
