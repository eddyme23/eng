#!/usr/bin/env bash
# Remove native VayDNS integration and restore direct SlowDNS ingress.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
unit_dir=/etc/systemd/system
slow_override="$unit_dir/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf"
install -d -m 700 "$state_dir" /var/backups/frimps-v6
exec 9>"$state_dir/.vaydns-install.lock"
flock -w 30 9 || exit 1
if [[ ! -f "$state_dir/vaydns.env" && ! -f $slow_override && ! -f $unit_dir/frimps-vaydns.service && ! -f $unit_dir/frimps-dns-dispatch.service && ! -d /etc/frimps-vaydns ]]; then
 bash "$script_dir/refresh-menu-v6.sh"
 echo 'No native VayDNS installation found; menu refreshed without restarting SlowDNS.'
 exit 0
fi
# This migration only handles the ENG integration; never rewrite other SSH/DNS settings.
[[ -f $unit_dir/frimps-slowdns.service ]] || { echo 'Managed SlowDNS unit is missing; restore it before removal.' >&2; exit 1; }
grep -Eq '^ExecStart=.*-udp [0-9.]+:53 .*127\.0\.0\.1:22$' "$unit_dir/frimps-slowdns.service" || {
 echo 'Original SlowDNS unit is not configured for public UDP 53. No change made.' >&2; exit 1;
}
backup=$(mktemp -d /var/backups/frimps-v6/remove-vaydns-XXXXXXXX)
for file in "$slow_override" "$state_dir/vaydns.env" "$state_dir/dns-dispatch.json"; do
 if [[ -f $file ]]; then cp --parents -a "$file" "$backup/"; fi
done
units=(frimps-vaydns.service frimps-dns-dispatch.service)
for unit in "${units[@]}"; do
 systemctl is-enabled --quiet "$unit" && touch "$backup/$unit.enabled" || true
 systemctl is-active --quiet "$unit" && touch "$backup/$unit.active" || true
done
recover() {
 trap - ERR
 echo "SlowDNS restoration failed; recovering the previous dispatcher. Backup: $backup" >&2
 for file in "$slow_override" "$state_dir/vaydns.env" "$state_dir/dns-dispatch.json"; do
  if [[ -f $backup$file ]]; then install -d "$(dirname "$file")"; cp -a "$backup$file" "$file"; fi
 done
 systemctl daemon-reload
 systemctl restart frimps-slowdns.service || true
 for unit in "${units[@]}"; do
  [[ ! -f $backup/$unit.enabled ]] || systemctl enable "$unit" || true
  [[ ! -f $backup/$unit.active ]] || systemctl start "$unit" || true
 done
 exit 1
}
trap recover ERR
echo "Removing VayDNS; current DNS tunnel sessions will disconnect. Backup: $backup"
for unit in frimps-dns-dispatch.service frimps-vaydns.service; do
 if systemctl cat "$unit" >/dev/null 2>&1; then systemctl disable --now "$unit"; fi
done
rm -f "$slow_override" "$state_dir/vaydns.env" "$state_dir/dns-dispatch.json"
systemctl daemon-reload
systemctl restart frimps-slowdns.service
for attempt in {1..20}; do
 if ss -H -lunp 'sport = :53' | grep -q sldns-server; then break; fi
 sleep 0.25
done
bash "$script_dir/slowdns-audit.sh" --local
trap - ERR
# Only integration-owned paths are removed. Keep credentials recoverable in backup.
if [[ -d /etc/frimps-vaydns ]]; then mv /etc/frimps-vaydns "$backup/vaydns-keys"; fi
for unit in frimps-vaydns frimps-dns-dispatch; do
 [[ ! -f $unit_dir/$unit.service ]] || cp -a "$unit_dir/$unit.service" "$backup/"
 rm -f "$unit_dir/$unit.service" "$unit_dir/$unit.service.d/70-frimps-log-limits.conf"
 rmdir "$unit_dir/$unit.service.d" 2>/dev/null || true
done
rm -f /usr/local/libexec/frimps-vaydns
for file in vaydns-install.sh vaydns-audit.sh rollback-vaydns.sh dns-dispatch.py; do
 rm -f "/usr/local/lib/frimps-v6/$file"
done
systemctl daemon-reload
bash "$script_dir/refresh-menu-v6.sh"
echo "VayDNS removed. SlowDNS restored on public UDP 53. Backup: $backup"
echo 'SlowDNS keys and SSH accounts were preserved. Reconnect existing SlowDNS profiles.'
