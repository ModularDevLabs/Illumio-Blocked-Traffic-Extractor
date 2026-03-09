#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
PROFILE_PATH="${PCE_PROFILE_PATH:-$ROOT_DIR/pce_profiles.json}"

echo "Running unit tests..."
env CGO_ENABLED=0 "$GO_BIN" test ./...

echo "Running live PCE smoke test..."
env RUN_LIVE_PCE_TESTS=1 PCE_PROFILE_PATH="$PROFILE_PATH" CGO_ENABLED=0 "$GO_BIN" test -run TestLivePCEConnectionAndDirectServiceQuery -v .

echo "Smoke tests passed."
