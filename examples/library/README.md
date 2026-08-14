<p align="center">
  <img src="../../assets/logo.svg" alt="Wiretap" width="420"/>
</p>

# Library example

Minimal Go embedding of Wiretap:

```bash
go run ./examples/library
go run ./examples/library examples/thermostat/captures.hex
```

Blank-import `internal/analysis` and `internal/capture` to register the analyzer
and ingest adapters (same as the CLI).

See the [library section](../../README.md#library) in the product README.
