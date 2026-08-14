package capture

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// Importer loads captures from a specialized format.
// Wiretap analyzes authorized captures only — importers are ingest helpers,
// not network acquisition tools.
type Importer interface {
	Name() string
	CanHandle(path string, peek []byte) bool
	Import(path string, opts LoadOptions) (*wt.Dataset, error)
}

// PCAPImporter reads classic PCAP and basic PCAPNG (Enhanced Packet Blocks).
type PCAPImporter struct{}

func (PCAPImporter) Name() string { return "pcap" }

func (PCAPImporter) CanHandle(path string, peek []byte) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
		return true
	}
	if len(peek) < 4 {
		return false
	}
	magic := binary.LittleEndian.Uint32(peek[:4])
	switch magic {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a:
		return true
	}
	return false
}

func (p PCAPImporter) Import(path string, opts LoadOptions) (*wt.Dataset, error) {
	return ImportPCAP(path, opts)
}

// ImportPCAP loads UDP/TCP payloads (Ethernet+IPv4) or truncated frame bytes from a PCAP/PCAPNG file.
func ImportPCAP(path string, opts LoadOptions) (*wt.Dataset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: pcap too short", wt.ErrInvalidHex)
	}
	mtime := fileModTime(path)
	ds := wt.NewDataset(filepath.Base(path))
	magic := binary.LittleEndian.Uint32(data[:4])
	var payloads []pcapPkt
	switch magic {
	case 0x0a0d0d0a:
		payloads, err = parsePCAPNG(data)
	default:
		payloads, err = parsePCAP(data)
	}
	if err != nil {
		return nil, err
	}
	for i, pkt := range payloads {
		if opts.MaxMessages > 0 && ds.Len() >= opts.MaxMessages {
			markTruncated(ds, "max_messages", ds.Len())
			break
		}
		payload := pkt.Payload
		truncated := false
		if opts.MaxRecordBytes > 0 && len(payload) > opts.MaxRecordBytes {
			payload = payload[:opts.MaxRecordBytes]
			truncated = true
		}
		if len(payload) == 0 {
			continue
		}
		cap := captureTime(opts, mtime, i)
		if !pkt.TS.IsZero() {
			t := pkt.TS.UTC()
			cap = &t
		}
		if err := ds.Add(&wt.Message{
			ID:        fmt.Sprintf("pcap_%d_%s", i, hashID(payload)),
			Data:      append([]byte(nil), payload...),
			Source:    wt.Source{Kind: "pcap", Path: path, Offset: int64(pkt.Offset), Imported: "pcap"},
			Truncated: truncated,
			Captured:  cap,
			Metadata:  map[string]string{"filename": filepath.Base(path), "transport": pkt.Transport},
		}); err != nil {
			return nil, err
		}
	}
	if ds.Len() == 0 {
		return nil, fmt.Errorf("%w: no extractable payloads in pcap", wt.ErrNoMessages)
	}
	return ds, nil
}

type pcapPkt struct {
	Payload   []byte
	Offset    int
	TS        time.Time
	Transport string
}

func parsePCAP(data []byte) ([]pcapPkt, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("%w: missing pcap global header", wt.ErrInvalidHex)
	}
	magic := binary.LittleEndian.Uint32(data[:4])
	le := true
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		le = true
	case 0xd4c3b2a1, 0x4d3cb2a1:
		le = false
	default:
		return nil, fmt.Errorf("%w: unrecognized pcap magic 0x%08x", wt.ErrInvalidHex, magic)
	}
	u32 := func(b []byte) uint32 {
		if le {
			return binary.LittleEndian.Uint32(b)
		}
		return binary.BigEndian.Uint32(b)
	}
	u16 := func(b []byte) uint16 {
		if le {
			return binary.LittleEndian.Uint16(b)
		}
		return binary.BigEndian.Uint16(b)
	}
	network := u32(data[20:24])
	var out []pcapPkt
	off := 24
	for off+16 <= len(data) {
		tsSec := u32(data[off : off+4])
		tsUsec := u32(data[off+4 : off+8])
		incl := int(u32(data[off+8 : off+12]))
		off += 16
		if incl < 0 || off+incl > len(data) {
			break
		}
		frame := data[off : off+incl]
		payload, transport := extractPayload(frame, network)
		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)
		if magic == 0xa1b23c4d || magic == 0x4d3cb2a1 {
			ts = time.Unix(int64(tsSec), int64(tsUsec)*1000) // ns magic variants still usable
			_ = u16
		}
		out = append(out, pcapPkt{Payload: payload, Offset: off, TS: ts, Transport: transport})
		off += incl
	}
	return out, nil
}

func parsePCAPNG(data []byte) ([]pcapPkt, error) {
	// PCAPNG: Section Header (SHB), Interface Description (IDB),
	// Enhanced Packet (EPB), Simple Packet (SPB).
	var out []pcapPkt
	linktypes := map[uint32]uint16{} // interface id → linktype
	var ifaces []uint16
	off := 0
	u32 := binary.LittleEndian.Uint32
	u16 := binary.LittleEndian.Uint16
	for off+8 <= len(data) {
		blockType := u32(data[off : off+4])
		blockLen := int(u32(data[off+4 : off+8]))
		if blockLen < 12 || off+blockLen > len(data) {
			break
		}
		body := data[off+8 : off+blockLen-4]
		switch blockType {
		case 0x0a0d0d0a: // Section Header Block
			if len(body) >= 4 {
				bom := binary.LittleEndian.Uint32(body[0:4])
				if bom == 0x1a2b3c4d {
					u32 = binary.LittleEndian.Uint32
					u16 = binary.LittleEndian.Uint16
				} else if bom == 0x4d3c2b1a {
					u32 = binary.BigEndian.Uint32
					u16 = binary.BigEndian.Uint16
					blockLen = int(u32(data[off+4 : off+8]))
					if blockLen < 12 || off+blockLen > len(data) {
						break
					}
				}
			}
			linktypes = map[uint32]uint16{}
			ifaces = nil
		case 0x00000001: // Interface Description Block
			if len(body) >= 2 {
				lt := u16(body[0:2])
				id := uint32(len(ifaces))
				ifaces = append(ifaces, lt)
				linktypes[id] = lt
			}
		case 0x00000006: // Enhanced Packet Block
			if len(body) >= 20 {
				ifID := u32(body[0:4])
				tsHigh := u32(body[4:8])
				tsLow := u32(body[8:12])
				capLen := int(u32(body[12:16]))
				pkt := body[20:]
				if capLen > len(pkt) {
					capLen = len(pkt)
				}
				if capLen > 0 {
					frame := pkt[:capLen]
					lt := uint16(1)
					if v, ok := linktypes[ifID]; ok {
						lt = v
					} else if len(ifaces) > 0 {
						lt = ifaces[0]
					}
					payload, transport := extractPayload(frame, uint32(lt))
					ts := time.Unix(0, int64(uint64(tsHigh)<<32|uint64(tsLow)))
					out = append(out, pcapPkt{Payload: payload, Offset: off, TS: ts, Transport: transport})
				}
			}
		case 0x00000003: // Simple Packet Block
			if len(body) >= 4 {
				origLen := int(u32(body[0:4]))
				pkt := body[4:]
				capLen := origLen
				if capLen > len(pkt) {
					capLen = len(pkt)
				}
				if capLen > 0 {
					frame := pkt[:capLen]
					lt := uint16(1)
					if len(ifaces) > 0 {
						lt = ifaces[0]
					}
					payload, transport := extractPayload(frame, uint32(lt))
					out = append(out, pcapPkt{Payload: payload, Offset: off, Transport: transport})
				}
			}
		}
		off += blockLen
	}
	return out, nil
}

// ParsePCAPNGForFuzz exposes PCAPNG parsing for fuzz tests (must not panic).
func ParsePCAPNGForFuzz(data []byte) (n int, err error) {
	pkts, err := parsePCAPNG(data)
	return len(pkts), err
}

func extractPayload(frame []byte, network uint32) ([]byte, string) {
	// DLT_EN10MB = 1, DLT_RAW = 12/14, DLT_NULL = 0
	switch network {
	case 1: // Ethernet
		if len(frame) < 14 {
			return append([]byte(nil), frame...), "frame"
		}
		ethertype := binary.BigEndian.Uint16(frame[12:14])
		if ethertype == 0x0800 && len(frame) >= 34 { // IPv4
			p, t := extractIPPayload(frame[14:])
			return p, t
		}
		return append([]byte(nil), frame[14:]...), "ethernet"
	case 0: // null/loopback — often AF then IP
		if len(frame) > 4 {
			return extractIPPayload(frame[4:])
		}
	case 12, 14, 101: // raw IP
		return extractIPPayload(frame)
	}
	return append([]byte(nil), frame...), "frame"
}

func extractIPPayload(ip []byte) ([]byte, string) {
	if len(ip) < 20 {
		return append([]byte(nil), ip...), "ip"
	}
	vihl := ip[0]
	if vihl>>4 != 4 {
		return append([]byte(nil), ip...), "ip"
	}
	ihl := int(vihl&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return append([]byte(nil), ip...), "ip"
	}
	proto := ip[9]
	switch proto {
	case 6: // TCP
		if len(ip) < ihl+20 {
			return append([]byte(nil), ip[ihl:]...), "tcp"
		}
		dataOff := int(ip[ihl+12]>>4) * 4
		if dataOff < 20 || len(ip) < ihl+dataOff {
			return append([]byte(nil), ip[ihl:]...), "tcp"
		}
		return append([]byte(nil), ip[ihl+dataOff:]...), "tcp"
	case 17: // UDP
		if len(ip) < ihl+8 {
			return append([]byte(nil), ip[ihl:]...), "udp"
		}
		return append([]byte(nil), ip[ihl+8:]...), "udp"
	default:
		return append([]byte(nil), ip[ihl:]...), fmt.Sprintf("ip-proto-%d", proto)
	}
}
