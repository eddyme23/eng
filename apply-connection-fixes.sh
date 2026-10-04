#!/usr/bin/env bash
# Apply the routing and TLS startup fixes to an installed Frimps server.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
[[ -s "$state_dir/routes.json" && -s "$state_dir/runtime.env" ]] || { echo 'Frimps is not installed' >&2; exit 1; }
printf 'Applying connection fixes; the TLS restart will disconnect existing TCP 443 sessions.\n'
backup_dir="/var/backups/frimps-v6/connection-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup_dir"
cp -a /etc/haproxy/haproxy.cfg "$backup_dir/haproxy.cfg"
cp -a /usr/local/libexec/frimps-v6-tlsmux "$backup_dir/tlsmux.previous"
# Build into the backup directory first; leave the running binary in place
# until the new public routing configuration passes HAProxy validation.
V6_TLSMUX_OUTPUT="$backup_dir/build/tlsmux.new" bash "$script_dir/build-tlsmux.sh"
bash "$script_dir/render-routing.sh"
bash "$script_dir/validate-v6.sh"
haproxy -c -f "$state_dir/haproxy-443.cfg"
install -m 755 "$backup_dir/build/tlsmux.new" /usr/local/libexec/frimps-v6-tlsmux
install -m 600 "$state_dir/haproxy-443.cfg" /etc/haproxy/haproxy.cfg
systemctl restart frimps-v6-tlsmux.service
systemctl reload haproxy.service
bash "$script_dir/refresh-menu-v6.sh"
printf 'Connection fixes applied. Proxy backup: %s\n' "$backup_dir"
printf 'The TLS gateway restart disconnects existing sessions on TCP 443.\n'
