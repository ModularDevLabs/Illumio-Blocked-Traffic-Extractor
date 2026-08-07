#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

build_version="${ITT_VERSION:-}"
if [[ -z "$build_version" ]]; then
    build_version="$(git describe --tags --always --dirty 2>/dev/null || true)"
fi
if [[ -z "$build_version" ]]; then
    build_version="development"
fi
if [[ ! "$build_version" =~ ^[A-Za-z0-9._+-]+$ ]]; then
    echo "ITT_VERSION contains unsupported filename characters: $build_version" >&2
    exit 1
fi

build_target() {
    local target_os="$1"
    local target_arch="$2"
    local versioned_name="$3"
    local compatibility_name="$4"

    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build \
        -trimpath \
        -ldflags "-X main.appVersion=$build_version" \
        -o "$versioned_name" .
    cp "$versioned_name" "$compatibility_name"
    echo "Built $versioned_name"
}

go test ./...
build_target linux amd64 "IllumioTrafficTool_${build_version}_Linux" "IllumioTrafficTool_Linux"
build_target windows amd64 "IllumioTrafficTool_${build_version}_Windows.exe" "IllumioTrafficTool_Windows.exe"
build_target darwin amd64 "IllumioTrafficTool_${build_version}_MacOS_Intel" "IllumioTrafficTool_MacOS_Intel"
build_target darwin arm64 "IllumioTrafficTool_${build_version}_MacOS_AppleSilicon" "IllumioTrafficTool_MacOS_AppleSilicon"
