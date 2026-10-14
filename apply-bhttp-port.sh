#!/usr/bin/env bash
# Move managed BHTTP to TCP 90, leaving HCR and other listeners unchanged.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
unit=/etc/systemd/system/frimps-bhttp.service
[[ -f $unit && -s "$state_dir/bhttp.env" ]] || { echo 'Install BHTTP first using bhttp-install.sh.' >&2; exit 1; }
grep -q '^ExecStart=/opt/frimps-bhttp/bhttp-server ' "$unit" || { echo 'Unrecognized BHTTP unit; no change made.' >&2; exit 1; }
source "$state_dir/bhttp.env"
if [[ $BHTTP_PORT != 90 && -n $(ss -H -ltn 'sport = :90') ]]; then echo 'TCP 90 is occupied; no change made.' >&2; exit 1; fi
backup="/var/backups/frimps-v6/bhttp-port-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup"
cp -a "$unit" "$backup/frimps-bhttp.service"
cp -a "$state_dir/bhttp.env" "$backup/bhttp.env"
rollback() {
 cp -a "$backup/frimps-bhttp.service" "$unit"
 cp -a "$backup/bhttp.env" "$state_dir/bhttp.env"
 systemctl daemon-reload
 systemctl restart frimps-bhttp.service || true
}
trap 'rollback' ERR
sed -i -E 's/--port [0-9]+/--port 90/; s/^CapabilityBoundingSet=.*/CapabilityBoundingSet=CAP_NET_BIND_SERVICE/; /^AmbientCapabilities=/d' "$unit"
sed -i '/^CapabilityBoundingSet=/a AmbientCapabilities=CAP_NET_BIND_SERVICE' "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl restart frimps-bhttp.service
sleep 2
systemctl is-active --quiet frimps-bhttp.service
[[ -n $(ss -H -ltn 'sport = :90') ]]
sed -i 's/^BHTTP_PORT=.*/BHTTP_PORT=90/' "$state_dir/bhttp.env"
trap - ERR
bash "$script_dir/refresh-menu-v6.sh"
echo "BHTTP now listens on TCP 90. Backup: $backup"
echo 'Use port 90 in your BHTTP client and allow TCP 90 through any host/provider firewall.'
