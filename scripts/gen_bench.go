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
	root := "testdata/bench"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	mk := func(name string, msgs [][]byte) {
		dir := filepath.Join(root, name)
		_ = os.MkdirAll(dir, 0o755)
		var hex string
		for i, m := range msgs {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("m%02d.bin", i)), m, 0o644)
			hex += fmt.Sprintf("%x\n", m)
		}
		_ = os.WriteFile(filepath.Join(dir, "captures.hex"), []byte(hex), 0o644)
	}

	mk("tiny_fixed", [][]byte{
		{0xBE, 0xEF, 0x01, 0x00, 0x08, 0x00, 0x01, 0xAA},
		{0xBE, 0xEF, 0x01, 0x00, 0x08, 0x00, 0x02, 0xAB},
		{0xBE, 0xEF, 0x01, 0x00, 0x08, 0x00, 0x03, 0xAC},
	})

	var variable [][]byte
	for i := 0; i < 6; i++ {
		pay := make([]byte, 4+i)
		for j := range pay {
			pay[j] = byte(j + i)
		}
		b := []byte{0xCA, 0xFE, byte(8 + len(pay))}
		b = append(b, pay...)
		variable = append(variable, b)
	}
	mk("variable_payload", variable)

	var many [][]byte
	for i := 0; i < 8; i++ {
		b := make([]byte, 16)
		b[0], b[1] = 0x10, 0x20
		b[2] = byte(i % 4)
		binary.BigEndian.PutUint16(b[3:5], uint16(16))
		binary.BigEndian.PutUint16(b[5:7], uint16(i))
		binary.BigEndian.PutUint32(b[7:11], uint32(1700000000+i))
		b[11] = byte(i & 0x7)
		copy(b[12:], []byte("xx"))
		many = append(many, b)
	}
	mk("many_types", many)

	var nested [][]byte
	for i := 0; i < 5; i++ {
		n := 1 + i%3
		msg := []byte{0xD0, 0x0D, byte(n)}
		for e := 0; e < n; e++ {
			var eb [4]byte
			binary.BigEndian.PutUint32(eb[:], uint32(100*i+e))
			msg = append(msg, eb[:]...)
		}
		nested = append(nested, msg)
	}
	mk("nested", nested)

	var highEnt [][]byte
	for i := 0; i < 5; i++ {
		b := make([]byte, 32)
		for j := range b {
			b[j] = byte((i*31 + j*17) % 251)
		}
		highEnt = append(highEnt, b)
	}
	mk("high_entropy", highEnt)

	var csum [][]byte
	for i := 0; i < 6; i++ {
		msg := []byte{0xCC, 0x01, byte(i), byte(i + 1), byte(i + 2)}
		sum := crc32.ChecksumIEEE(msg)
		var cb [4]byte
		binary.BigEndian.PutUint32(cb[:], sum)
		msg = append(msg, cb[:]...)
		csum = append(csum, msg)
	}
	mk("checksum_heavy", csum)

	var constant [][]byte
	for i := 0; i < 5; i++ {
		b := []byte{0x11, 0x22, 0x33, 0x44, 0x55, byte(i), 0x66, 0x77}
		constant = append(constant, b)
	}
	mk("mostly_constant", constant)
	fmt.Println("wrote", root)
}
