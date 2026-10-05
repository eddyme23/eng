#!/usr/bin/env bash
# Isolate the upstream raw-packet UDP server from all other protocol traffic.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
ns=frimps-socksip
iface="${V6_PUBLIC_INTERFACE:-$(ip -4 route show default | awk '/default/ {print $5; exit}')}"
[[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo 'invalid public interface' >&2; exit 1; }
command -v nft >/dev/null || { echo 'install nftables' >&2; exit 1; }
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
  # Network namespaces have their own forwarding setting. Host forwarding
  # does not enable traffic from the upstream server's tun0 to sipns0.
  ip netns exec "$ns" sysctl -q -w net.ipv4.ip_forward=1
  install -d -m 755 "/etc/netns/$ns"
  printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' > "/etc/netns/$ns/resolv.conf"
  {
    if nft list table ip frimps_socksip >/dev/null 2>&1; then echo 'delete table ip frimps_socksip'; fi
    cat <<EOF
 table ip frimps_socksip {
  chain forward {
   type filter hook forward priority filter; policy accept;
   iifname "$iface" oifname "siphost0" udp dport 1195-3999 accept
   iifname "siphost0" oifname "$iface" accept
   iifname "$iface" oifname "siphost0" ct state established,related accept
  }
  chain postrouting {
   type nat hook postrouting priority srcnat; policy accept;
   ip saddr 169.254.240.2/32 oifname "$iface" masquerade
  }
 }
EOF
  } | nft -f -
  ;;
 remove)
  if nft list table ip frimps_socksip >/dev/null 2>&1; then nft delete table ip frimps_socksip; fi
  ip netns delete "$ns" 2>/dev/null || true
  ip link delete siphost0 2>/dev/null || true
  ;;
 *) echo 'usage: socksip-network.sh {apply|remove}' >&2; exit 1 ;;
esac
