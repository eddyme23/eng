#!/usr/bin/env bash
# Read-only diagnostics: never print passwords or account database contents.
set -uo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
echo '=== SocksIP service status ==='
systemctl --no-pager --full status frimps-socksip-network frimps-v6-udp-routing frimps-socksip || true
echo '=== Recent SocksIP startup and network errors ==='
journalctl -u frimps-socksip -u frimps-socksip-network --no-pager -n 70 || true
echo '=== Public interface and namespace routes ==='
ip -4 route show default
ip -brief address show siphost0 || true
ip netns list
ip -n frimps-socksip -brief address || true
ip -n frimps-socksip route show || true
echo '=== Managed native firewall rules ==='
nft list table ip frimps_v6_udp || true
nft list table ip frimps_socksip || true
echo '=== Forwarding setting ==='
sysctl net.ipv4.ip_forward
ip netns exec frimps-socksip sysctl net.ipv4.ip_forward || true
echo '=== Namespace internet and DNS test ==='
if command -v curl >/dev/null; then
  ip netns exec frimps-socksip curl -4 -sS --connect-timeout 5 --max-time 12 -o /dev/null -w 'HTTP %{http_code}; connect %{time_connect}s; total %{time_total}s\n' https://www.cloudflare.com/cdn-cgi/trace || true
fi
echo '=== Binary format and shared-library requirements ==='
if command -v file >/dev/null; then file /etc/frimps-socksip/udpServer; fi
if [[ -f /etc/frimps-socksip/udpServer ]]; then ldd /etc/frimps-socksip/udpServer 2>&1 || true; fi
echo '=== Namespace firewall created by upstream binary ==='
ip netns exec frimps-socksip nft list ruleset || true
echo 'Client must use direct VPS IPv4, SocksIP UDP mode, port 1195-3999, and a non-expired SSH account.'
echo 'This report does not establish packet arrival or a successful client login.'
