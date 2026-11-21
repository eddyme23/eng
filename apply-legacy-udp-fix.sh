#!/usr/bin/env bash
# Repair the audited UDP-Custom catch-all; keep native nftables as policy owner.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
nft list table ip frimps_v6_udp >/dev/null
install -d -m 700 /var/backups/frimps-v6
backup="$(mktemp -d "/var/backups/frimps-v6/legacy-udp-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
umask 077
snapshot() {
 local tool="$1" destination="$2" status=0
 shift 2
 "$tool" "$@" > "$destination" 2> "$destination.stderr" || status=$?
 if [[ -s "$destination.stderr" ]]; then
  sed "s/^/[$tool snapshot, exit $status] /" "$destination.stderr" >&2
 fi
 if ((status)); then
  echo "Firewall snapshot failed for $tool; cleanup has not started. Backup: $backup" >&2
  return "$status"
 fi
}
snapshot nft "$backup/nftables.rules" list ruleset
for tool in iptables-save iptables-nft-save iptables-legacy-save ip6tables-save ip6tables-nft-save ip6tables-legacy-save; do
 if command -v "$tool" >/dev/null; then
   if snapshot "$tool" "$backup/$tool.rules" -t nat; then :
   elif grep -Eqi 'Table does not exist|Address family not supported|Protocol not supported' "$backup/$tool.rules.stderr"; then
     echo "[SKIP] Snapshot backend $tool has no NAT table."
   else exit 1; fi
 fi
done
# Preserve prior managed unit/drop-ins as well as the live rule snapshots.
for unit in frimps-firewall-migration.service frimps-udp-custom.service frimps-v6-udp-routing.service netfilter-persistent.service nftables.service iptables.service ip6tables.service; do
  if [[ -f "/etc/systemd/system/$unit" ]]; then cp -a "/etc/systemd/system/$unit" "$backup/$unit"; fi
  if [[ -d "/etc/systemd/system/$unit.d" ]]; then cp -a "/etc/systemd/system/$unit.d" "$backup/$unit.d"; fi
done
bash "$script_dir/install-firewall-guard.sh"
# Explicit execution repairs an already-active RemainAfterExit migration unit.
systemctl restart frimps-firewall-migration.service

echo "Removed only obsolete ENG UDP Custom catch-all rules. Firewall backup: $backup"
echo 'No VPN service was restarted; SlowDNS domain, keys, MTU, backend and account policy are unchanged.'
echo 'UDP Custom loses CAP_NET_ADMIN on its next start/restart or reboot.'
echo 'Reconnect affected UDP clients; old conntrack NAT mappings may persist until they expire.'
echo 'Verify with: bash ./retire-iptables-rules.sh --check; bash ./slowdns-audit.sh'
