# Polished mystery-corpus demo for Wiretap (Windows PowerShell).
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
Set-Location $Root

$Hex = "examples\mystery\captures.hex"
$Map = Join-Path $env:TEMP "wiretap-mystery-map.svg"

$Wt = $null
$BinExe = Join-Path $Root "bin\wiretap.exe"
$Bin = Join-Path $Root "bin\wiretap"
if (Test-Path $BinExe) {
    $Wt = $BinExe
} elseif (Test-Path $Bin) {
    $Wt = $Bin
} elseif (Get-Command wiretap -ErrorAction SilentlyContinue) {
    $Wt = "wiretap"
} else {
    Write-Host "==> building bin\wiretap.exe"
    New-Item -ItemType Directory -Force -Path (Join-Path $Root "bin") | Out-Null
    go build -o $BinExe ./cmd/wiretap
    $Wt = $BinExe
}

Write-Host "==> wiretap version"
& $Wt version

Write-Host ""
Write-Host "==> analyze (mystery)"
& $Wt analyze --budget normal $Hex

Write-Host ""
Write-Host "==> explain at field:4"
& $Wt explain --at field:4 $Hex

Write-Host ""
Write-Host "==> visualize -> $Map"
& $Wt visualize $Hex -o $Map
Write-Host "wrote $Map"

Write-Host ""
Write-Host "==> eval (quick)"
& $Wt eval --n 20 --budget quick

Write-Host ""
Write-Host "Demo complete. Try: $Wt tui $Hex"
