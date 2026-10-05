#!/usr/bin/env bash
# Managed UDP ingress policy for the remaining v6 services.
# Uses native nftables; legacy iptables rules are retired by the updater.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
chain="V6_UDP_INGRESS"
action="${1:-apply}"
public_if="${V6_PUBLIC_INTERFACE:-}"

die() { echo "v6 UDP routing: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die 'run as root'
command -v nft >/dev/null 2>&1 || die 'install nftables'

sync_routes_metadata() {
  local routes="$state_dir/routes.json" tmp
  [[ -s "$routes" ]] && command -v jq >/dev/null 2>&1 || return 0
  tmp="$(mktemp "$state_dir/.routes.json.XXXXXX")"
  jq '.udpCustomRanges = ["50001-65535"] | .socksipRanges = ["1195-3999"] | .protocols = ["ssh", "slowdns", "udp-custom", "socksip", "openvpn", "wireguard", "zivpn", "hysteria1", "hysteria2"] | .udpPriority = ["slowdns", "hysteria2", "openvpn", "wireguard", "zivpn", "hysteria1", "socksip", "udp-custom"]' "$routes" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$routes"
}

if [[ -z "$public_if" ]]; then
  public_if="$(ip -4 route show default | awk '/default/ {print $5; exit}')"
fi
[[ -n "$public_if" ]] || die 'could not determine public interface; set V6_PUBLIC_INTERFACE'

nft_apply() {
  # Native nftables policy. The table is dedicated to v6 and is recreated
  # atomically, so unrelated firewall state is never rewritten.
  local policy
  policy="$(mktemp)"
  {
  if nft list table ip frimps_v6_udp >/dev/null 2>&1; then echo "delete table ip frimps_v6_udp"; fi
  cat <<EOF
table ip frimps_v6_udp {
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  iifname "$public_if" udp dport { 53, 443, 1194, 4000 } accept
  iifname "$public_if" udp dport 6000-19999 dnat to :5667
  iifname "$public_if" udp dport 20000-50000 dnat to :36712
  iifname "$public_if" udp dport 1195-3999 dnat to 169.254.240.2
  iifname "$public_if" udp dport 50001-65535 dnat to :36717
  iifname "$public_if" meta l4proto udp accept
 }
}
EOF
  } > "$policy"
  if ! nft -c -f "$policy"; then rm -f "$policy"; return 1; fi
  if [[ "$action" == check ]]; then rm -f "$policy"; echo "UDP nftables syntax check passed."; return; fi
  if ! nft -f "$policy"; then rm -f "$policy"; return 1; fi
  rm -f "$policy"
  install -d -m 700 "$state_dir"
  printf 'interface=%s\nbackend=nftables\n' "$public_if" > "$state_dir/udp-routing.env"
  chmod 600 "$state_dir/udp-routing.env"
  sync_routes_metadata
  echo "Applied managed nftables UDP routing on $public_if."
}
remove() {
  if nft list table ip frimps_v6_udp >/dev/null 2>&1; then nft delete table ip frimps_v6_udp; fi
  rm -f "$state_dir/udp-routing.env"
  echo 'Removed managed nftables UDP table.'
}
case "$action" in apply|check) nft_apply ;; remove) remove ;; *) die 'usage: udp-routing.sh {apply|remove}' ;; esac
