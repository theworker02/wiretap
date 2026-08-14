//go:build ignore

package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: gen <thermostat|tlv|array> outdir")
		os.Exit(1)
	}
	kind, out := os.Args[1], os.Args[2]
	os.MkdirAll(out, 0755)
	switch kind {
	case "thermostat":
		genThermostat(out)
	case "tlv":
		genTLV(out)
	case "array":
		genArray(out)
	}
}

func genThermostat(out string) {
	var hexlines []string
	for i := 0; i < 8; i++ {
		b := []byte{'T', 'H', 1, byte(i % 3)}
		var tb [2]byte
		binary.BigEndian.PutUint16(tb[:], uint16(200+i*5))
		b = append(b, tb[:]...)
		binary.BigEndian.PutUint16(tb[:], 210)
		b = append(b, tb[:]...)
		b = append(b, byte(i&1))
		sum := crc32.ChecksumIEEE(b)
		var cb [4]byte
		binary.BigEndian.PutUint32(cb[:], sum)
		b = append(b, cb[:]...)
		name := filepath.Join(out, fmt.Sprintf("msg_%02d.bin", i))
		os.WriteFile(name, b, 0644)
		os.WriteFile(name+".labels.yaml", []byte(fmt.Sprintf("zone: \"%d\"\ntemp: \"%d\"\n", i%3, 200+i*5)), 0644)
		hexlines = append(hexlines, fmt.Sprintf("%x", b))
	}
	writeHex(out, hexlines)
}

func genTLV(out string) {
	var hexlines []string
	for i := 0; i < 6; i++ {
		b := []byte{0xA5}
		name := []byte(fmt.Sprintf("dev%d", i))
		b = append(b, 1, byte(len(name)))
		b = append(b, name...)
		b = append(b, 2, 2, byte(10+i), byte(20+i))
		b = append(b, 3, 1, byte(i&3))
		namef := filepath.Join(out, fmt.Sprintf("msg_%02d.bin", i))
		os.WriteFile(namef, b, 0644)
		os.WriteFile(namef+".labels.yaml", []byte(fmt.Sprintf("device: \"%d\"\n", i)), 0644)
		hexlines = append(hexlines, fmt.Sprintf("%x", b))
	}
	writeHex(out, hexlines)
}

func genArray(out string) {
	var hexlines []string
	for i := 0; i < 6; i++ {
		n := 1 + i%3
		b := []byte{0x52, 0x31, 0x01, byte(n)} // magic R1, ver, count
		for e := 0; e < n; e++ {
			var eb [4]byte
			binary.BigEndian.PutUint32(eb[:], uint32(1000+i*10+e))
			b = append(b, eb[:]...)
		}
		name := filepath.Join(out, fmt.Sprintf("msg_%02d.bin", i))
		os.WriteFile(name, b, 0644)
		os.WriteFile(name+".labels.yaml", []byte(fmt.Sprintf("count: \"%d\"\n", n)), 0644)
		hexlines = append(hexlines, fmt.Sprintf("%x", b))
	}
	writeHex(out, hexlines)
}

func writeHex(out string, lines []string) {
	s := ""
	for _, l := range lines {
		s += l + "\n"
	}
	os.WriteFile(filepath.Join(out, "captures.hex"), []byte(s), 0644)
}
