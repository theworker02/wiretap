.PHONY: build test lint fuzz bench clean install mystery examples eval visualize \
	release-snapshot fmt vet race doctor

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.4.0)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILT   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/theworker02/wiretap/pkg/wiretap.Version=$(VERSION) \
           -X github.com/theworker02/wiretap/pkg/wiretap.Commit=$(COMMIT) \
           -X github.com/theworker02/wiretap/pkg/wiretap.Built=$(BUILT)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/wiretap ./cmd/wiretap

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/wiretap

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed; skipped"
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi

fuzz:
	go test ./internal/capture -fuzz=FuzzParseHex -fuzztime=5s
	go test ./internal/capture -fuzz=FuzzPCAPNG -fuzztime=5s
	go test ./internal/inference -fuzz=FuzzChecksum -fuzztime=5s
	go test ./schema -fuzz=FuzzSchemaYAML -fuzztime=5s
	go test ./schema -fuzz=FuzzSchemaJSON -fuzztime=5s
	go test ./schema -fuzz=FuzzKaitaiGen -fuzztime=5s

bench: testdata/bench/tiny_fixed/captures.hex
	go test ./internal/analysis ./internal/eval -bench=. -benchmem -count=1

eval: build
	./bin/wiretap eval --n 50 --budget normal

visualize: build
	./bin/wiretap visualize examples/mystery/captures.hex -o map.svg

doctor: build
	./bin/wiretap doctor

release-snapshot:
	goreleaser release --snapshot --clean

testdata/bench/tiny_fixed/captures.hex:
	go run ./scripts/gen_bench.go testdata/bench

mystery:
	go run ./scripts/gen_mystery.go examples/mystery

examples:
	go run ./scripts/gen_examples.go thermostat examples/thermostat
	go run ./scripts/gen_examples.go tlv examples/tlv
	go run ./scripts/gen_examples.go array examples/array_records

clean:
	rm -rf bin/ map.svg
