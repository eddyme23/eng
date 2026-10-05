#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
command -v nft >/dev/null || { echo 'install nftables' >&2; exit 1; }
iface="${V6_PUBLIC_INTERFACE:-$(ip -4 route show default | awk '/default/ {print $5; exit}')}"
[[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || exit 1
case "${1:-}" in
 apply)
  sysctl -q -w net.ipv4.ip_forward=1
  {
   if nft list table ip frimps_v6_wg >/dev/null 2>&1; then echo 'delete table ip frimps_v6_wg'; fi
   cat <<EOF
table ip frimps_v6_wg {
 chain forward { type filter hook forward priority filter; policy accept; iifname "wg0" accept; oifname "wg0" ct state established,related accept; }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept; ip saddr 10.0.0.0/24 oifname "$iface" masquerade; }
}
EOF
  } | nft -f -
  ;;
 remove) if nft list table ip frimps_v6_wg >/dev/null 2>&1; then nft delete table ip frimps_v6_wg; fi ;;
 *) echo 'usage: wireguard-nat.sh {apply|remove}' >&2; exit 2 ;;
esac
