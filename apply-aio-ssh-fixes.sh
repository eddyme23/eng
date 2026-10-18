#!/usr/bin/env bash
# Apply deferred legacy SSH bridging and separate SlowDNS from Dropbear.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
unit=/etc/systemd/system/frimps-slowdns.service
python3 - <<'PY_CHECK'
import socket
with socket.create_connection(('127.0.0.1',22),timeout=5) as s:
 s.settimeout(5)
 if not s.recv(256).startswith(b'SSH-'): raise SystemExit('OpenSSH 22 did not return an SSH banner; no changes applied.')
PY_CHECK
if [[ -f $unit ]]; then
 grep -q '^ExecStart=/etc/slowdns/sldns-server .*127.0.0.1:\(143\|22\)$' "$unit" || { echo 'Unrecognized SlowDNS unit; no changes applied.' >&2; exit 1; }
fi
bash "$script_dir/apply-connection-fixes.sh"
if [[ -f $unit ]]; then
 backup="/var/backups/frimps-v6/slowdns-$(date -u +%Y%m%dT%H%M%SZ).service"
 cp -a "$unit" "$backup"
 sed -i 's/127.0.0.1:143/127.0.0.1:22/; s/frimps-v6-dropbear.service/ssh.service/g; s/SlowDNS to Dropbear bridge/SlowDNS to OpenSSH bridge/' "$unit"
 systemctl daemon-reload
 if ! systemctl restart frimps-slowdns.service; then
  cp -a "$backup" "$unit"
  systemctl daemon-reload
  systemctl restart frimps-slowdns.service || true
  echo 'SlowDNS restart failed; previous unit restored.' >&2
  exit 1
 fi
fi
# Clear old pending Dropbear connections, then keep all dependent gateways running.
systemctl restart frimps-v6-dropbear.service frimps-v6-sshws.service frimps-v6-payloadgate.service frimps-v6-tlsmux.service
echo 'Applied AIO-style legacy bridging and SlowDNS OpenSSH backend.'
echo 'Test TG connect/disconnect cycles. Legacy payload clients must send their SSH identification after HTTP 101/200.'
