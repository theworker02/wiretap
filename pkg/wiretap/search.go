package wiretap

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// SearchHit is one occurrence of a byte pattern inside a dataset message.
type SearchHit struct {
	MessageID    string `json:"message_id"`
	MessageIndex int    `json:"message_index"`
	Offset       int    `json:"offset"`
	Length       int    `json:"length"`
	ContextHex   string `json:"context_hex"`
}

const searchContextBytes = 8

// Search finds non-overlapping occurrences of pattern in every message.
// An empty pattern is an invalid config; a nil dataset is empty.
func (d *Dataset) Search(pattern []byte) ([]SearchHit, error) {
	if len(pattern) == 0 {
		return nil, fmt.Errorf("%w: empty search pattern", ErrInvalidConfig)
	}
	if d == nil {
		return nil, ErrEmptyDataset
	}
	hits := make([]SearchHit, 0)
	for i, message := range d.Messages {
		if message == nil || len(message.Data) == 0 {
			continue
		}
		data := message.Data
		start := 0
		for start <= len(data)-len(pattern) {
			rel := bytes.Index(data[start:], pattern)
			if rel < 0 {
				break
			}
			offset := start + rel
			ctxStart := offset - searchContextBytes
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := offset + len(pattern) + searchContextBytes
			if ctxEnd > len(data) {
				ctxEnd = len(data)
			}
			hits = append(hits, SearchHit{
				MessageID:    message.ID,
				MessageIndex: i,
				Offset:       offset,
				Length:       len(pattern),
				ContextHex:   hex.EncodeToString(data[ctxStart:ctxEnd]),
			})
			start = offset + len(pattern)
		}
	}
	return hits, nil
}
