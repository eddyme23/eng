#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -s /etc/frimps-v6/routes.json ]] || { echo 'install Frimps first' >&2; exit 1; }
backup="/var/backups/frimps-v6/udp-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup" /usr/local/libexec
cp /etc/frimps-v6/routes.json "$backup/routes.json"
if command -v nft >/dev/null 2>&1; then
  nft list ruleset > "$backup/nftables.rules"
fi
# SocksIP's managed network requires iptables. Ensure its backup tool exists
# before calling it, even on servers originally configured with native nft.
if ! command -v iptables-save >/dev/null 2>&1; then
  apt-get update
  apt-get install -y iptables
fi
iptables-save > "$backup/iptables.rules"
[[ ! -f /usr/local/libexec/frimps-v6-udp-routing ]] || cp /usr/local/libexec/frimps-v6-udp-routing "$backup/udp-routing.sh"
echo 'Updating UDP ranges. UDP Custom clients must use 50001-65535 afterward.'
bash "$script_dir/socksip-install.sh"
install -m 700 "$script_dir/udp-routing.sh" /usr/local/libexec/frimps-v6-udp-routing
systemctl enable --now frimps-socksip-network.service
systemctl restart frimps-v6-udp-routing.service
systemctl enable --now frimps-socksip.service
systemctl restart frimps-socksip.service
bash "$script_dir/refresh-menu-v6.sh"
systemctl is-active --quiet frimps-v6-udp-routing frimps-socksip-network frimps-socksip
echo "UDP update applied; backup: $backup"
echo 'Client tests required: UDP Custom port 53000; SocksIP UDP port 2000, VPS IPv4 and managed SSH credentials.'
