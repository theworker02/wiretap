package capture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPCAPNG_IDB_EPB_SPB(t *testing.T) {
	// Minimal PCAPNG: SHB + IDB + EPB + SPB with Ethernet/IPv4/UDP payloads.
	payloadEPB := []byte{0xaa, 0xbb}
	payloadSPB := []byte{0xcc, 0xdd, 0xee}

	mkUDPFrame := func(payload []byte) []byte {
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:2], 1111)
		binary.BigEndian.PutUint16(udp[2:4], 2222)
		binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
		copy(udp[8:], payload)
		ip := make([]byte, 20+len(udp))
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		ip[9] = 17
		copy(ip[20:], udp)
		eth := make([]byte, 14+len(ip))
		binary.BigEndian.PutUint16(eth[12:14], 0x0800)
		copy(eth[14:], ip)
		return eth
	}

	frame1 := mkUDPFrame(payloadEPB)
	frame2 := mkUDPFrame(payloadSPB)

	var buf []byte
	// SHB
	shbBody := make([]byte, 16)
	binary.LittleEndian.PutUint32(shbBody[0:4], 0x1a2b3c4d) // BOM LE
	binary.LittleEndian.PutUint16(shbBody[4:6], 1)
	binary.LittleEndian.PutUint16(shbBody[6:8], 0)
	shb := makeBlock(0x0a0d0d0a, shbBody)
	buf = append(buf, shb...)

	// IDB linktype=1 ethernet
	idbBody := make([]byte, 8)
	binary.LittleEndian.PutUint16(idbBody[0:2], 1)
	idb := makeBlock(0x00000001, idbBody)
	buf = append(buf, idb...)

	// EPB
	epbBody := make([]byte, 20+len(frame1)+pad4(len(frame1)))
	binary.LittleEndian.PutUint32(epbBody[0:4], 0) // if id
	binary.LittleEndian.PutUint32(epbBody[12:16], uint32(len(frame1)))
	binary.LittleEndian.PutUint32(epbBody[16:20], uint32(len(frame1)))
	copy(epbBody[20:], frame1)
	epb := makeBlock(0x00000006, epbBody[:20+len(frame1)+pad4(len(frame1))])
	buf = append(buf, epb...)

	// SPB
	spbBody := make([]byte, 4+len(frame2)+pad4(len(frame2)))
	binary.LittleEndian.PutUint32(spbBody[0:4], uint32(len(frame2)))
	copy(spbBody[4:], frame2)
	spb := makeBlock(0x00000003, spbBody[:4+len(frame2)+pad4(len(frame2))])
	buf = append(buf, spb...)

	dir := t.TempDir()
	path := filepath.Join(dir, "t.pcapng")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := ImportPCAP(path, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 2 {
		t.Fatalf("messages=%d want 2", ds.Len())
	}
	if string(ds.Messages[0].Data) != string(payloadEPB) {
		t.Fatalf("epb payload=%x", ds.Messages[0].Data)
	}
	if string(ds.Messages[1].Data) != string(payloadSPB) {
		t.Fatalf("spb payload=%x", ds.Messages[1].Data)
	}
}

func makeBlock(typ uint32, body []byte) []byte {
	// pad body to 4 bytes
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := 12 + len(body) // type+len + body + len
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:4], typ)
	binary.LittleEndian.PutUint32(b[4:8], uint32(total))
	copy(b[8:], body)
	binary.LittleEndian.PutUint32(b[total-4:], uint32(total))
	return b
}

func pad4(n int) int {
	if n%4 == 0 {
		return 0
	}
	return 4 - n%4
}
