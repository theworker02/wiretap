# Building on Windows

GNU Make targets assume a Unix-like shell for some helpers (`lint` gofmt check,
`fuzz`, `clean`). Core commands work via Go directly:

```powershell
go test ./...
go build -o bin\wiretap.exe .\cmd\wiretap
go run .\scripts\gen_mystery.go examples\mystery
.\bin\wiretap.exe analyze examples\mystery\captures.hex
```

Polished mystery demo:

```powershell
.\scripts\demo.ps1
```

With GNU Make (Git Bash / WSL / MSYS2), `make build test doctor` works the same
as on Linux. Default version stamp is **0.4.0** when tags are unavailable.
