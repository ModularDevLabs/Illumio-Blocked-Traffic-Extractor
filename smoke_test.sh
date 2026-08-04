#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

GO_BIN="${GO_BIN:-go}"

echo "Running unit tests..."
env CGO_ENABLED=0 "$GO_BIN" test ./...

echo "Running live PCE smoke test..."
env RUN_LIVE_PCE_TESTS=1 CGO_ENABLED=0 "$GO_BIN" test -run TestLivePCEConnectionAndDirectServiceQuery -v .

echo "Smoke tests passed."
