package eval

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand"
	"time"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// FieldTruth describes one ground-truth field for evaluation.
type FieldTruth struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Kind   string `json:"kind"` // magic,version,type,length,seq,timestamp,flags,string,array,checksum,bytes
	Endian string `json:"endian,omitempty"`
}

// ProtocolSpec configures synthetic protocol generation.
type ProtocolSpec struct {
	Seed       int64
	Count      int
	WithArray  bool
	WithString bool
	WithCRC    bool
}

// GroundTruth holds fields for a generated protocol family.
type GroundTruth struct {
	Fields []FieldTruth `json:"fields"`
	Name   string       `json:"name"`
}

// Generate creates a dataset and ground truth for evaluation.
func Generate(spec ProtocolSpec) (*wt.Dataset, *GroundTruth, error) {
	if spec.Count <= 0 {
		spec.Count = 8
	}
	rng := rand.New(rand.NewSource(spec.Seed))
	ds := wt.NewDataset("synth")
	gt := &GroundTruth{Name: "synth_v1"}
	base := time.Unix(1700000000, 0).UTC()
	for i := 0; i < spec.Count; i++ {
		typ := byte(1 + rng.Intn(3))
		seq := uint16(100 + i)
		flags := byte(rng.Intn(8))
		var body []byte
		body = append(body, 0xBE, 0xEF)
		body = append(body, 0x01)
		body = append(body, typ)
		lenOff := len(body)
		body = append(body, 0, 0)
		seqOff := len(body)
		var sb [2]byte
		binary.BigEndian.PutUint16(sb[:], seq)
		body = append(body, sb[:]...)
		flagsOff := len(body)
		body = append(body, flags)
		tsOff := len(body)
		var tb [4]byte
		binary.BigEndian.PutUint32(tb[:], uint32(base.Add(time.Duration(i)*time.Second).Unix()))
		body = append(body, tb[:]...)

		strOff := -1
		if spec.WithString {
			s := fmt.Sprintf("msg-%02d", i)
			strOff = len(body)
			body = append(body, byte(len(s)))
			body = append(body, []byte(s)...)
		}
		arrOff := -1
		countOff := -1
		nElem := 0
		if spec.WithArray {
			nElem = 1 + rng.Intn(3)
			countOff = len(body)
			body = append(body, byte(nElem))
			arrOff = len(body)
			for e := 0; e < nElem; e++ {
				var eb [4]byte
				binary.BigEndian.PutUint32(eb[:], uint32(rng.Intn(1<<16)))
				body = append(body, eb[:]...)
			}
		}
		pad := rng.Intn(3)
		for p := 0; p < pad; p++ {
			body = append(body, byte(p))
		}
		total := len(body)
		if spec.WithCRC {
			total += 4
		}
		binary.BigEndian.PutUint16(body[lenOff:lenOff+2], uint16(total))
		if spec.WithCRC {
			sum := crc32.ChecksumIEEE(body)
			var cb [4]byte
			binary.BigEndian.PutUint32(cb[:], sum)
			body = append(body, cb[:]...)
		}
		cap := base.Add(time.Duration(i) * time.Second)
		if err := ds.Add(&wt.Message{
			ID:       fmt.Sprintf("synth_%02d", i),
			Data:     body,
			Source:   wt.Source{Kind: "synth"},
			Captured: &cap,
			Labels:   map[string]string{"type": fmt.Sprintf("%d", typ), "seq": fmt.Sprintf("%d", seq)},
		}); err != nil {
			return nil, nil, err
		}
		if i == 0 {
			gt.Fields = []FieldTruth{
				{Name: "magic", Offset: 0, Length: 2, Kind: "magic"},
				{Name: "version", Offset: 2, Length: 1, Kind: "version"},
				{Name: "type", Offset: 3, Length: 1, Kind: "type"},
				{Name: "length", Offset: 4, Length: 2, Kind: "length", Endian: "be"},
				{Name: "seq", Offset: seqOff, Length: 2, Kind: "seq", Endian: "be"},
				{Name: "flags", Offset: flagsOff, Length: 1, Kind: "flags"},
				{Name: "timestamp", Offset: tsOff, Length: 4, Kind: "timestamp", Endian: "be"},
			}
			if strOff >= 0 {
				gt.Fields = append(gt.Fields, FieldTruth{Name: "string", Offset: strOff, Length: 1, Kind: "string"})
			}
			if countOff >= 0 {
				gt.Fields = append(gt.Fields, FieldTruth{Name: "count", Offset: countOff, Length: 1, Kind: "array"})
				gt.Fields = append(gt.Fields, FieldTruth{Name: "records", Offset: arrOff, Length: 4, Kind: "array"})
			}
			if spec.WithCRC {
				gt.Fields = append(gt.Fields, FieldTruth{Name: "crc32", Offset: -4, Length: 4, Kind: "checksum", Endian: "be"})
			}
		}
	}
	return ds, gt, nil
}
