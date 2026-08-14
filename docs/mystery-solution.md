# Mystery protocol — maintainer ground truth

Fictional **Orbital Beacon** framing (big-endian):

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 2 | magic | `0xBE71` |
| 2 | 1 | version | `1` |
| 3 | 1 | type | 1=ping, 2=telemetry, 3=alert |
| 4 | 2 | length | total message length |
| 6 | 2 | sequence | monotonic counter |
| 8 | 4 | timestamp | unix seconds |
| 12 | 1 | flags | bitfield |
| 13 | … | payload | variable |
| end-2 | 2 | checksum | CRC-16-CCITT over prefix |

Regenerate: `go run ./scripts/gen_mystery.go examples/mystery`
