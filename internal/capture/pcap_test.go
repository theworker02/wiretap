package capture

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

func TestCapturedFromMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := LoadPath(path, LoadOptions{Binary: true})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 1 {
		t.Fatalf("len=%d", ds.Len())
	}
	if ds.Messages[0].Captured == nil {
		t.Fatal("expected Captured from mtime")
	}
}

func TestMaxMessagesTruncation(t *testing.T) {
	dir := t.TempDir()
	hexPath := filepath.Join(dir, "multi.hex")
	content := "010203\n040506\n070809\n0a0b0c\n"
	if err := os.WriteFile(hexPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := LoadPath(hexPath, LoadOptions{OnePerLine: true, MaxMessages: 2})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 2 {
		t.Fatalf("want 2 got %d", ds.Len())
	}
	if ds.Meta["truncated"] != "true" {
		t.Fatalf("expected truncation meta: %v", ds.Meta)
	}
}

func TestSyntheticPCAP(t *testing.T) {
	// Build classic PCAP with one Ethernet+IPv4+UDP packet carrying 4 payload bytes.
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 1234)
	binary.BigEndian.PutUint16(udp[2:4], 5678)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 17 // UDP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	copy(ip[20:], udp)

	eth := make([]byte, 14+len(ip))
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)

	global := make([]byte, 24)
	binary.LittleEndian.PutUint32(global[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(global[4:6], 2)
	binary.LittleEndian.PutUint16(global[6:8], 4)
	binary.LittleEndian.PutUint32(global[20:24], 1) // ethernet

	rec := make([]byte, 16+len(eth))
	binary.LittleEndian.PutUint32(rec[0:4], 1700000000)
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(eth)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(eth)))
	copy(rec[16:], eth)

	dir := t.TempDir()
	path := filepath.Join(dir, "t.pcap")
	if err := os.WriteFile(path, append(global, rec...), 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := ImportPCAP(path, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 1 {
		t.Fatalf("messages=%d", ds.Len())
	}
	got := ds.Messages[0].Data
	if string(got) != string(payload) {
		t.Fatalf("payload=%x want %x", got, payload)
	}
	if ds.Messages[0].Captured == nil {
		t.Fatal("expected packet timestamp")
	}
}

func TestPublicIngestRegistered(t *testing.T) {
	b, err := wt.ParseHex("01 02 03 04")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Fatalf("%x", b)
	}
	ds, err := wt.LoadHex([]string{"aabb", "ccdd"})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 2 {
		t.Fatalf("len=%d", ds.Len())
	}
}

func TestCapturedOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	_ = os.WriteFile(path, []byte{1, 2, 3}, 0o644)
	ts := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	ds, err := LoadPath(path, LoadOptions{Binary: true, CapturedOverride: &ts})
	if err != nil {
		t.Fatal(err)
	}
	if !ds.Messages[0].Captured.Equal(ts) {
		t.Fatalf("got %v", ds.Messages[0].Captured)
	}
}

func TestFollowPCAPStableFile(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 1234)
	binary.BigEndian.PutUint16(udp[2:4], 5678)
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
	global := make([]byte, 24)
	binary.LittleEndian.PutUint32(global[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(global[4:6], 2)
	binary.LittleEndian.PutUint16(global[6:8], 4)
	binary.LittleEndian.PutUint32(global[20:24], 1)
	rec := make([]byte, 16+len(eth))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(eth)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(eth)))
	copy(rec[16:], eth)

	dir := t.TempDir()
	path := filepath.Join(dir, "grow.pcap")
	if err := os.WriteFile(path, append(global, rec...), 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := FollowPCAP(context.Background(), path, FollowPCAPOptions{
		PollInterval: 50 * time.Millisecond,
		MaxIdlePolls: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Len() != 1 {
		t.Fatalf("messages=%d", ds.Len())
	}
	if ds.Meta["source"] != "pcap-follow" {
		t.Fatalf("meta=%v", ds.Meta)
	}
}
