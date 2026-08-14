package schema_test

import (
	"testing"

	"github.com/theworker02/wiretap/schema"
)

func TestSchemaRoundTripAndGenerate(t *testing.T) {
	off0, off2 := 0, 2
	s := &schema.Schema{
		Name: "demo", Version: "0.1.0", Endian: "be",
		Fields: []schema.Field{
			{Name: "magic", Offset: &off0, Length: 2, Type: "bytes", Value: "be71"},
			{Name: "version", Offset: &off2, Length: 1, Type: "u8"},
		},
	}
	b, err := schema.MarshalYAML(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := schema.UnmarshalYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	if errs := schema.Validate(s2); len(errs) != 0 {
		t.Fatal(errs)
	}
	code, err := schema.GenerateGo(s2, "protocol")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(code, "func ParseDemo") {
		t.Fatalf("missing ParseDemo:\n%s", code)
	}
	if !contains(code, "ParseError") {
		t.Fatal("missing ParseError")
	}
}

func TestValidateRejectsBad(t *testing.T) {
	s := &schema.Schema{Name: "x", Fields: []schema.Field{{Name: "a", Type: ""}}}
	errs := schema.Validate(s)
	if len(errs) == 0 {
		t.Fatal("expected errors")
	}
}

func TestKaitaiAndWiresharkSmoke(t *testing.T) {
	off := 0
	s := &schema.Schema{
		Name: "demo", Version: "0.1.0", Endian: "be",
		Fields: []schema.Field{
			{Name: "magic", Offset: &off, Length: 2, Type: "u16", Endian: "be"},
		},
	}
	ksy, err := schema.GenerateKaitai(s)
	if err != nil || !contains(ksy, "meta:") {
		t.Fatalf("kaitai: %v %s", err, ksy)
	}
	lua, err := schema.GenerateWiresharkLua(s, "demo")
	if err != nil || !contains(lua, "Proto(") {
		t.Fatalf("lua: %v %s", err, lua)
	}
	d := schema.Diff(s, s)
	if len(d.Changes) != 0 {
		t.Fatalf("diff self: %v", d)
	}
}

func FuzzSchemaJSON(f *testing.F) {
	f.Add([]byte(`{"name":"t","fields":[{"name":"a","type":"u8"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := schema.UnmarshalJSON(b)
		if err != nil {
			return
		}
		_ = schema.Validate(s)
		_, _ = schema.GenerateKaitai(s)
	})
}

func FuzzKaitaiGen(f *testing.F) {
	f.Add([]byte("name: t\nfields:\n  - name: a\n    type: u8\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := schema.UnmarshalYAML(b)
		if err != nil {
			return
		}
		_, _ = schema.GenerateKaitai(s)
		_, _ = schema.GenerateWiresharkLua(s, "x")
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || stringIndex(s, sub) >= 0)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestGenerateGoSanitizesNamesAndSignedInts(t *testing.T) {
	off0, off4 := 0, 4
	s := &schema.Schema{
		Name: "captures.hex", Version: "0.1.0", Endian: "be",
		Fields: []schema.Field{
			{Name: "magic", Offset: &off0, Length: 2, Type: "bytes"},
			{Name: "payload_len", Offset: &off4, Length: 8, Type: "i64", Endian: "le"},
		},
	}
	code, err := schema.GenerateGo(s, "beacon")
	if err != nil {
		t.Fatal(err)
	}
	if contains(code, "Captures.hex") || contains(code, "type Captures.hex") {
		t.Fatalf("invalid Go type name retained:\n%s", code)
	}
	if !contains(code, "type CapturesHex struct") {
		t.Fatalf("expected CapturesHex type:\n%s", code)
	}
	if !contains(code, "func ParseCapturesHex") {
		t.Fatalf("expected ParseCapturesHex:\n%s", code)
	}
	if !contains(code, "int64(binary.LittleEndian.Uint64") {
		t.Fatalf("expected signed i64 decode:\n%s", code)
	}
	if contains(code, "PayloadLen = append([]byte") {
		t.Fatalf("signed field incorrectly assigned as []byte:\n%s", code)
	}
}
