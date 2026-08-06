#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl --user disable --now illumio-traffic-scheduler.service 2>/dev/null || true
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/illumio-traffic-scheduler.service"
  systemctl --user daemon-reload
  echo "Illumio traffic scheduler user service removed."
  exit 0
fi

binary_path="${1:-$(pwd)/IllumioTrafficTool_Linux}"
binary_path="$(realpath "$binary_path")"
if [[ ! -x "$binary_path" ]]; then
  echo "Executable not found: $binary_path" >&2
  exit 1
fi
if [[ "$binary_path" == *['"'\\$'\n']* ]]; then
  echo "Executable path cannot contain quotes, backslashes, or newlines." >&2
  exit 1
fi

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$unit_dir"
unit_path="$unit_dir/illumio-traffic-scheduler.service"

escaped_binary="$(printf '%s' "$binary_path" | sed -e 's/[\\&|]/\\&/g')"
sed \
  -e "s|@@BINARY@@|$escaped_binary|g" \
  "$(dirname "${BASH_SOURCE[0]}")/service/illumio-traffic-scheduler.service.in" > "$unit_path"
chmod 600 "$unit_path"
systemctl --user daemon-reload
systemctl --user enable --now illumio-traffic-scheduler.service
echo "Illumio traffic scheduler installed and started as a user service."
echo "Check it with: systemctl --user status illumio-traffic-scheduler.service"
