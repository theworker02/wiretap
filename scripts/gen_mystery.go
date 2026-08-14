//go:build ignore

// Package mysterygen builds the fictional "Orbital Beacon" protocol captures.
// Layout (big-endian unless noted):
//
//	0-1   magic      u16  = 0xOB71 ("orbital beacon")
//	2     version    u8   = 1
//	3     type       u8   = 1=ping, 2=telemetry, 3=alert
//	4-5   length     u16  = total message length
//	6-7   sequence   u16  counter
//	8-11  timestamp  u32  unix seconds
//	12    flags      u8   bitfield
//	13..n-3 payload  bytes
//	n-2..n-1 crc16-ccitt over [0:n-2]
package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"time"
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

func build(msgType byte, seq uint16, ts uint32, flags byte, payload []byte) []byte {
	// length includes header(13) + payload + crc(2) = 15 + len(payload)
	total := 15 + len(payload)
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], 0xBE71)
	buf[2] = 1
	buf[3] = msgType
	binary.BigEndian.PutUint16(buf[4:6], uint16(total))
	binary.BigEndian.PutUint16(buf[6:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ts)
	buf[12] = flags
	copy(buf[13:], payload)
	sum := crc16CCITT(buf[:total-2])
	binary.BigEndian.PutUint16(buf[total-2:], sum)
	_ = crc32.ChecksumIEEE // keep hash available for alternate experiments
	return buf
}

func main() {
	out := "examples/mystery"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	_ = os.MkdirAll(out, 0o755)
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC).Unix()

	var lines []string
	var labeled []string

	for i := 0; i < 12; i++ {
		seq := uint16(100 + i)
		ts := uint32(base + int64(i*5))
		var typ byte
		var flags byte
		var payload []byte
		switch i % 3 {
		case 0:
			typ = 1
			flags = 0x01
			payload = []byte("ping")
		case 1:
			typ = 2
			flags = 0x03
			payload = []byte{byte(i), byte(i * 2), byte(i * 3), 0x00}
		default:
			typ = 3
			flags = 0x05
			payload = []byte("ALERT")
		}
		msg := build(typ, seq, ts, flags, payload)
		lines = append(lines, fmt.Sprintf("%x", msg))
		labeled = append(labeled, fmt.Sprintf("%x  # type=%d seq=%d", msg, typ, seq))
	}

	// Mixed hex styles for parser tolerance demo
	hexFile := filepath.Join(out, "captures.hex")
	f, err := os.Create(hexFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "# Orbital Beacon mystery captures (fictional). One message per line.")
	for i, line := range lines {
		switch i % 4 {
		case 0:
			fmt.Fprintln(f, line)
		case 1:
			// spaced
			var spaced string
			for j := 0; j < len(line); j += 2 {
				if j > 0 {
					spaced += " "
				}
				spaced += line[j : j+2]
			}
			fmt.Fprintln(f, spaced)
		case 2:
			// 0x + colons
			var c string
			for j := 0; j < len(line); j += 2 {
				if j > 0 {
					c += ":"
				}
				c += line[j : j+2]
			}
			fmt.Fprintln(f, "0x"+c)
		default:
			fmt.Fprintln(f, line)
		}
	}

	// Binary files with labels for diff
	for i, line := range lines {
		raw := mustDecode(line)
		name := fmt.Sprintf("msg_%02d.bin", i)
		_ = os.WriteFile(filepath.Join(out, name), raw, 0o644)
		typ := raw[3]
		lab := fmt.Sprintf("type: \"%d\"\nseq: \"%d\"\n", typ, 100+i)
		_ = os.WriteFile(filepath.Join(out, name+".labels.yaml"), []byte(lab), 0o644)
	}

	// Labeled cohort file for differential analysis tutorial
	_ = os.WriteFile(filepath.Join(out, "README.md"), []byte(mysteryReadme), 0o644)
	_ = labeled
	fmt.Println("wrote", hexFile)
}

func mustDecode(hexs string) []byte {
	dst := make([]byte, len(hexs)/2)
	for i := 0; i < len(dst); i++ {
		var b byte
		fmt.Sscanf(hexs[i*2:i*2+2], "%02x", &b)
		dst[i] = b
	}
	return dst
}

const mysteryReadme = `# Mystery protocol captures

These captures belong to a deliberately undocumented fictional protocol
("Orbital Beacon"). Use them to exercise Wiretap offline:

` + "```" + `bash
wiretap analyze examples/mystery/captures.hex
wiretap entropy examples/mystery/captures.hex
wiretap checksum examples/mystery/captures.hex
wiretap cluster examples/mystery/
wiretap schema infer examples/mystery/captures.hex
` + "```" + `

No ground-truth schema is shipped for end users — discover structure from evidence.
`
