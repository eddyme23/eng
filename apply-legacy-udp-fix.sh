#!/usr/bin/env bash
# Repair the audited UDP-Custom catch-all; keep native nftables as policy owner.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
nft list table ip frimps_v6_udp >/dev/null
nft list table ip frimps_socksip >/dev/null
backup="/var/backups/frimps-v6/legacy-udp-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup"
umask 077
nft list ruleset > "$backup/nftables.rules"
for tool in iptables-save iptables-legacy-save ip6tables-save ip6tables-legacy-save; do
 if command -v "$tool" >/dev/null; then "$tool" > "$backup/$tool.rules"; fi
done
install -m 700 "$script_dir/retire-iptables-rules.sh" /usr/local/libexec/frimps-retire-iptables-rules
bash "$script_dir/retire-iptables-rules.sh"
# Run after persistent legacy restores and the UDP-Custom backend at boot.
cat >/etc/systemd/system/frimps-firewall-migration.service <<'EOF'
[Unit]
Description=Retire prior Frimps iptables rules after native nftables setup
After=netfilter-persistent.service frimps-v6-udp-routing.service frimps-socksip-network.service frimps-v6-wireguard-nat.service frimps-udp-custom.service
Requires=frimps-v6-udp-routing.service frimps-socksip-network.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/frimps-retire-iptables-rules
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now frimps-firewall-migration.service
systemctl restart frimps-firewall-migration.service
echo "Removed matching legacy catch-all rules. Firewall backup: $backup"
echo 'Reconnect the app to create a new UDP flow; existing NAT mappings can remain until they expire.'
echo 'Recheck France with bash ./slowdns-audit.sh and a client connection.'
