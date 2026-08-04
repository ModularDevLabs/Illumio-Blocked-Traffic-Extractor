#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o IllumioTrafficTool_Linux .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o IllumioTrafficTool_Windows.exe .
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o IllumioTrafficTool_MacOS_Intel .
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o IllumioTrafficTool_MacOS_AppleSilicon .
