#!/usr/bin/env bash
set -euo pipefail

label="com.modulardevlabs.illumio-traffic-scheduler"
plist_path="$HOME/Library/LaunchAgents/$label.plist"

if [[ "${1:-}" == "--uninstall" ]]; then
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  rm -f "$plist_path"
  echo "Illumio traffic scheduler LaunchAgent removed."
  exit 0
fi

binary_path="${1:-$(pwd)/IllumioTrafficTool_MacOS_AppleSilicon}"
binary_dir="$(cd "$(dirname "$binary_path")" && pwd)"
binary_path="$binary_dir/$(basename "$binary_path")"
if [[ ! -x "$binary_path" ]]; then
  echo "Executable not found: $binary_path" >&2
  exit 1
fi

mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}
sed_escape() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}
escaped_binary="$(sed_escape "$(xml_escape "$binary_path")")"
escaped_home="$(sed_escape "$(xml_escape "$HOME")")"
sed \
  -e "s|@@BINARY@@|$escaped_binary|g" \
  -e "s|@@HOME@@|$escaped_home|g" \
  "$(dirname "${BASH_SOURCE[0]}")/service/com.modulardevlabs.illumio-traffic-scheduler.plist.in" > "$plist_path"
chmod 600 "$plist_path"
launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$plist_path"
echo "Illumio traffic scheduler installed and started as a LaunchAgent."
