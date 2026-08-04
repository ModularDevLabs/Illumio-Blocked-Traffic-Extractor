#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

npx --yes tailwindcss@3.4.17 \
  -i frontend/tailwind.input.css \
  -o frontend/tailwind.css \
  --content './frontend/*.html' \
  --minify
