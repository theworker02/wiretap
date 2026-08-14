#!/usr/bin/env bash
# Polished mystery-corpus demo for Wiretap (Unix / Git Bash / WSL).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HEX="examples/mystery/captures.hex"
MAP="${TMPDIR:-/tmp}/wiretap-mystery-map.svg"

if [[ -x ./bin/wiretap ]]; then
  WT=./bin/wiretap
elif command -v wiretap >/dev/null 2>&1; then
  WT=wiretap
else
  echo "==> building bin/wiretap"
  go build -o bin/wiretap ./cmd/wiretap
  WT=./bin/wiretap
fi

echo "==> wiretap version"
"$WT" version || true

echo ""
echo "==> analyze (mystery)"
"$WT" analyze --budget normal "$HEX"

echo ""
echo "==> explain at field:4"
"$WT" explain --at field:4 "$HEX"

echo ""
echo "==> visualize -> $MAP"
"$WT" visualize "$HEX" -o "$MAP"
echo "wrote $MAP"

echo ""
echo "==> eval (quick)"
"$WT" eval --n 20 --budget quick

echo ""
echo "Demo complete. Try: $WT tui $HEX"
