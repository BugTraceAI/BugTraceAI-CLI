#!/bin/bash
# Build all Go fuzzers for the BugTraceAI Hybrid Engine
#
# Usage: ./tools/build_fuzzers.sh
#
# This script pre-compiles all Go fuzzer binaries. The binaries will be
# placed in tools/bin/ and used by the hybrid XSS/SSRF/IDOR/LFI engines.
#
# Note: Go fuzzers will also be compiled on-demand if not pre-built.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"

# Create bin directory
mkdir -p "$BIN_DIR"

echo "🔧 Building Go fuzzers for BugTraceAI Hybrid Engine..."
echo ""

# Build each fuzzer
for fuzzer_dir in "$SCRIPT_DIR"/go-*-fuzzer; do
    if [ -d "$fuzzer_dir" ]; then
        fuzzer_name=$(basename "$fuzzer_dir")
        binary_name="${fuzzer_name/go-/}"
        binary_name="${binary_name/-fuzzer/}"
        binary_name="go-${binary_name}-fuzzer"

        echo "📦 Building $fuzzer_name..."

        cd "$fuzzer_dir"

        if [ -f "main.go" ]; then
            go build -o "$BIN_DIR/$binary_name" main.go
            echo "   ✅ Built: $BIN_DIR/$binary_name"
        else
            echo "   ⚠️  Skipped: No main.go found"
        fi

        cd "$SCRIPT_DIR"
    fi
done

echo ""
echo "✨ Build complete! Binaries are in: $BIN_DIR"
echo ""
ls -la "$BIN_DIR"
