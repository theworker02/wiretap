# Code generators

## Go

```bash
wiretap generate go schema.yaml -o parse.go --package protocol
# or
wiretap generate schema.yaml -o parse.go
```

## Kaitai Struct

```bash
wiretap generate kaitai schema.yaml -o protocol.ksy
```

Emits a reviewable `.ksy` stub. Nested types and arrays may need hand-tuning.

## Wireshark Lua

```bash
wiretap generate wireshark schema.yaml -o protocol.lua --package myproto
```

Stub dissector — register a port yourself after review. Authorized captures only.
