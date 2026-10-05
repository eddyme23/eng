#!/usr/bin/env bash
# Migration only: remove exact rules created by previous Frimps releases.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || exit 1
iface="${V6_PUBLIC_INTERFACE:-$(ip -4 route show default | awk '/default/ {print $5; exit}')}"
[[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || exit 1
# Native replacement must be installed before legacy UDP ingress is retired.
nft list table ip frimps_v6_udp >/dev/null
nft list table ip frimps_socksip >/dev/null
for tool in iptables iptables-legacy; do
 command -v "$tool" >/dev/null 2>&1 || continue
 del() { local table="$1"; shift; while "$tool" -t "$table" -C "$@" 2>/dev/null; do "$tool" -t "$table" -D "$@"; done; }
 del nat PREROUTING -i "$iface" -p udp -j V6_UDP_INGRESS
 # Do not flush a chain still referenced by another interface.
 if "$tool" -t nat -S 2>/dev/null | grep -q -- '-j V6_UDP_INGRESS'; then
   echo 'Legacy UDP chain still referenced; retaining it for the other interface.' >&2
 else
   if "$tool" -t nat -S V6_UDP_INGRESS >/dev/null 2>&1; then
     "$tool" -t nat -F V6_UDP_INGRESS
     "$tool" -t nat -X V6_UDP_INGRESS
   fi
 fi
 del nat POSTROUTING -s 169.254.240.2/32 -o "$iface" -j MASQUERADE
 del filter FORWARD -i "$iface" -o siphost0 -p udp --dport 1195:3999 -j ACCEPT
 del filter FORWARD -i siphost0 -o "$iface" -j ACCEPT
 del filter FORWARD -i "$iface" -o siphost0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
 if nft list table ip frimps_v6_wg >/dev/null 2>&1; then
   del filter FORWARD -i wg0 -j ACCEPT
   del filter FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   del nat POSTROUTING -s 10.0.0.0/24 -o "$iface" -j MASQUERADE
 fi
done
echo 'Prior Frimps iptables rules retired; unrelated firewall rules retained.'
