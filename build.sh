#!/usr/bin/env bash
# build.sh — Cross-compile the Echo-Location DNS scanner for all target platforms.
#
# Usage:
#   chmod +x build.sh
#   ./build.sh
#
# Outputs are written to ./bin/.  Binary sizes are printed after each build.
#
# Requires: Go 1.22+ with cross-compilation support (included in the standard
# Go distribution — no additional toolchain needed for the listed targets).

set -euo pipefail

# ---------------------------------------------------------------------------
# Build flags
#   -trimpath   remove local FS paths from binary (safe for distribution)
#   -s -w       strip symbol table + DWARF (reduces binary size ~30%)
# ---------------------------------------------------------------------------
GOFLAGS="-trimpath -ldflags=-s -w"

mkdir -p bin

# ---------------------------------------------------------------------------
# Target matrix: "GOOS/GOARCH/package_dir"
#
# echocatcher is intentionally omitted for android/arm64: binding port 53 on
# Android requires root or a custom VPN service.
# ---------------------------------------------------------------------------
targets=(
    "linux/amd64/scattergun"
    "linux/amd64/echocatcher"
    "android/arm64/scattergun"
    "linux/arm64/scattergun"
    "linux/arm64/echocatcher"
    "darwin/arm64/scattergun"
    "darwin/arm64/echocatcher"
)

echo "=== Echo-Location build ==="
echo "Go version: $(go version)"
echo ""

ok=0
fail=0

for target in "${targets[@]}"; do
    IFS='/' read -r goos goarch pkg <<< "$target"
    out="bin/${pkg}-${goos}-${goarch}"

    printf "Building %-45s ... " "$out"

    if GOOS="$goos" GOARCH="$goarch" go build $GOFLAGS -o "$out" "./${pkg}/" 2>&1; then
        size=$(du -sh "$out" | cut -f1)
        echo "OK  (${size})"
        (( ok++ )) || true
    else
        echo "FAILED"
        (( fail++ )) || true
    fi
done

echo ""
echo "=== Summary: ${ok} succeeded, ${fail} failed ==="

if [[ $fail -gt 0 ]]; then
    exit 1
fi
