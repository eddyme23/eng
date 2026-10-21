#!/usr/bin/env bash
# Read-only local checks; not proof of mobile browsing.
set -uo pipefail
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
[[ ! -r "$state_dir/bhttp.env" ]] || source "$state_dir/bhttp.env"
systemctl status frimps-bhttp.service --no-pager --full || true
systemctl show frimps-bhttp.service -p ExecStart -p MemoryCurrent -p MemoryMax -p NRestarts --no-pager || true
for port in ${BHTTP_PORTS:-${BHTTP_PORT:-90}}; do ss -H -ltnp "( sport = :$port )"; done
if [[ ${BHTTP_ENGINE:-} == crisdev ]]; then
 python3 "$(dirname "$0")/bhttp-probe.py" --ports ${BHTTP_PORTS:-$BHTTP_PORT} || true
else
 systemctl status frimps-bhttp-alt.socket frimps-bhttp-alt.service --no-pager || true
fi
journalctl -u frimps-bhttp.service -n 60 --no-pager || true
echo 'Local BHP1 probes do not establish successful SSH authentication or mobile browsing.'
