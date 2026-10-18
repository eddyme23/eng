#!/usr/bin/env bash
# Optional, reversible DNS response-size trial. No other protocol is restarted.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
mtu="${1:-}"
[[ $# == 1 && $mtu =~ ^[0-9]{3,4}$ ]] && ((10#$mtu >= 512 && 10#$mtu <= 1232)) || { echo 'Use: bash ./apply-slowdns-mtu.sh 512 (trial) or 1232 (restore default).' >&2; exit 1; }
mtu=$((10#$mtu))
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
unit=/etc/systemd/system/frimps-slowdns.service
grep -q '^ExecStart=/etc/slowdns/sldns-server .*127.0.0.1:22$' "$unit" || { echo 'Unrecognized SlowDNS unit; no changes made.' >&2; exit 1; }
backup="/var/backups/frimps-v6/slowdns-mtu-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup" "$state_dir"
cp -a "$unit" "$backup/slowdns.service"
[[ ! -f "$state_dir/slowdns.env" ]] || cp -a "$state_dir/slowdns.env" "$backup/slowdns.env"
rollback() {
 cp -a "$backup/slowdns.service" "$unit"
 if [[ -f "$backup/slowdns.env" ]]; then cp -a "$backup/slowdns.env" "$state_dir/slowdns.env"; else rm -f "$state_dir/slowdns.env"; fi
 systemctl daemon-reload
 systemctl restart frimps-slowdns.service || true
}
trap rollback ERR
V6_STATE_DIR="$state_dir" python3 - <<'PY'
import os,re
from pathlib import Path
unit=Path('/etc/systemd/system/frimps-slowdns.service')
source=unit.read_text()
source=re.sub(r'^Environment=FRIMPS_SLOWDNS_MTU=.*\n','',source,flags=re.M)
source=re.sub(r'^EnvironmentFile=-[^\n]*/slowdns\.env\n','',source,flags=re.M)
source=source.replace('[Service]\n','[Service]\nEnvironment=FRIMPS_SLOWDNS_MTU=1232\nEnvironmentFile=-'+os.environ['V6_STATE_DIR']+'/slowdns.env\n')
source=re.sub(r' -mtu (?:[0-9]+|\$\{FRIMPS_SLOWDNS_MTU\})','',source)
source=source.replace('ExecStart=/etc/slowdns/sldns-server ', 'ExecStart=/etc/slowdns/sldns-server -mtu ${FRIMPS_SLOWDNS_MTU} ')
unit.write_text(source)
PY
umask 077
printf 'FRIMPS_SLOWDNS_MTU=%s\n' "$mtu" > "$state_dir/slowdns.env"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl restart frimps-slowdns.service
sleep 1
systemctl is-active --quiet frimps-slowdns.service
trap - ERR
echo "SlowDNS maximum DNS response size: $mtu bytes. Backup: $backup"
echo 'This is a compatibility trial; smaller responses reduce throughput. Reconnect and test browsing.'
echo 'Restore the default with: bash ./apply-slowdns-mtu.sh 1232'
