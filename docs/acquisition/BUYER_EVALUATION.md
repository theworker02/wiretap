# Buyer evaluation â€” Wiretap

## Goal

In 15â€“45 minutes, verify the Product builds or runs as documented and that proprietary notices are present.

## Steps

1. Confirm root `LICENSE` is proprietary and `ACQUISITION.md` exists.
2. Skim `README.md` install/run claims.
3. Execute:

```
```
 __        ___ ____  _____ _____  _    ____
 \ \      / (_|  _ \| ____|_   _|/ \  |  _ \
  \ \ /\ / /| | |_) |  _|   | | / _ \ | |_) |
   \ V  V / | |  _ <| |___  | |/ ___ \|  __/
    \_/\_/  |_|_| \_\_____| |_/_/   \_\_|
```
```text
$ wiretap analyze examples/mystery/captures.hex
Wiretap Analysis Report
  length @ 0x04     confidence=High
  checksum trailer  confidence=High
  Ã¢â‚¬Â¦
```
```bash
go install github.com/theworker02/wiretap/cmd/wiretap@v0.5.0
```
```bash
git clone https://github.com/theworker02/wiretap.git
cd wiretap
go build -o bin/wiretap ./cmd/wiretap
```
```bash
go build -ldflags "-X github.com/theworker02/wiretap/pkg/wiretap.Version=0.5.0" -o bin/wiretap ./cmd/wiretap
```
```bash
wiretap doctor
wiretap catalog
wiretap search --ascii HTTP examples/mystery/captures.hex
wiretap analyze examples/mystery/captures.hex
wiretap stats examples/mystery/captures.hex --limit 16
wiretap summary examples/mystery/captures.hex
wiretap explain --at field:0 examples/mystery/captures.hex
wiretap visualize examples/mystery/captures.hex -o map.svg
```
```bash
wiretap format --hex "8a:01:00:0c"
wiretap search --hex DEAD captures.bin
wiretap lint draft.yaml
wiretap catalog
```

4. Run tests if present (`npm test`, `pytest`, `cargo test`, `go test ./...`, etc.).
5. Record README vs observed behavior gaps in workpapers.

## Pass criteria

- [ ] Clone succeeds
- [ ] Documented happy path works **or** failure is explained
- [ ] Minimal path needs no surprise secrets
- [ ] License notices intact

*Updated: 2026-09-22*
