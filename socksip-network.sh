#!/usr/bin/env bash
# Isolate the upstream raw-packet UDP server from all other protocol traffic.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
ns=frimps-socksip
iface="${V6_PUBLIC_INTERFACE:-$(ip -4 route show default | awk '/default/ {print $5; exit}')}"
[[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo 'invalid public interface' >&2; exit 1; }
remove_rule() { local table="$1"; shift; while iptables -t "$table" -C "$@" 2>/dev/null; do iptables -t "$table" -D "$@"; done; }
case "${1:-}" in
 apply)
  if ! ip netns list | awk '{print $1}' | grep -qx "$ns"; then
    ip link show siphost0 >/dev/null 2>&1 && { echo 'siphost0 is already in use' >&2; exit 1; }
    ip netns add "$ns"
    ip link add siphost0 type veth peer name sipns0
    ip link set sipns0 netns "$ns"
  fi
  ip addr replace 169.254.240.1/30 dev siphost0
  ip link set siphost0 up
  ip -n "$ns" addr replace 169.254.240.2/30 dev sipns0
  ip -n "$ns" link set lo up
  ip -n "$ns" link set sipns0 up
  ip -n "$ns" route replace default via 169.254.240.1 dev sipns0
  sysctl -q -w net.ipv4.ip_forward=1
  install -d -m 755 "/etc/netns/$ns"
  printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' > "/etc/netns/$ns/resolv.conf"
  # Dedicated rules, removed by exact match on teardown.
  iptables -t nat -C POSTROUTING -s 169.254.240.2/32 -o "$iface" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 169.254.240.2/32 -o "$iface" -j MASQUERADE
  iptables -C FORWARD -i "$iface" -o siphost0 -p udp --dport 1195:3999 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$iface" -o siphost0 -p udp --dport 1195:3999 -j ACCEPT
  iptables -C FORWARD -i siphost0 -o "$iface" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i siphost0 -o "$iface" -j ACCEPT
  iptables -C FORWARD -i "$iface" -o siphost0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$iface" -o siphost0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ;;
 remove)
  remove_rule nat POSTROUTING -s 169.254.240.2/32 -o "$iface" -j MASQUERADE
  remove_rule filter FORWARD -i "$iface" -o siphost0 -p udp --dport 1195:3999 -j ACCEPT
  remove_rule filter FORWARD -i siphost0 -o "$iface" -j ACCEPT
  remove_rule filter FORWARD -i "$iface" -o siphost0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip netns delete "$ns" 2>/dev/null || true
  ip link delete siphost0 2>/dev/null || true
  ;;
 *) echo 'usage: socksip-network.sh {apply|remove}' >&2; exit 1 ;;
esac
