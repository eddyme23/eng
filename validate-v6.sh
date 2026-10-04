#!/usr/bin/env bash
set -euo pipefail
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
fail=0
check() { if "$@"; then printf '[ok] %s\n' "$*"; else printf '[fail] %s\n' "$*" >&2; fail=1; fi; }
for file in routes.json backends.json runtime.env haproxy-443.cfg nginx-main-tls.conf nginx-plain.conf nginx-ssh-only.conf tlsmux.service payloadgate.service; do
  check test -s "$state_dir/$file"
done
check jq -e '.protocols == ["ssh", "slowdns", "udp-custom", "openvpn", "wireguard", "zivpn", "hysteria1", "hysteria2"]' "$state_dir/routes.json"
check jq -e '.udpPriority == ["slowdns", "hysteria2", "openvpn", "wireguard", "zivpn", "hysteria1", "udp-custom"]' "$state_dir/routes.json"
check jq -e '.udpCustomRanges == ["1-52", "54-442", "444-1193", "1195-3999", "4001-5299", "5300-5999", "50001-65535"]' "$state_dir/routes.json"
check jq -e 'any(.publicRoutes[]; .path == "/openvpn" and .backend == "openvpn-websocket:10081")' "$state_dir/backends.json"
for port in 80 443 8080 8880 2082 2086; do check grep -q "bind :$port$" "$state_dir/haproxy-443.cfg"; done
check grep -q 'use_backend openvpn_websocket if openvpn_ws' "$state_dir/haproxy-443.cfg"
check grep -q 'default_backend ssh_http_gateway' "$state_dir/haproxy-443.cfg"
check grep -q 'server openvpn_websocket 127.0.0.1:10081' "$state_dir/haproxy-443.cfg"
check grep -q 'location = /' "$state_dir/nginx-main-tls.conf"
check grep -q -- '-ssh-target 127.0.0.1:143' "$state_dir/tlsmux.service"
check grep -q -- '-ws-target 127.0.0.1:3103' "$state_dir/payloadgate.service"
[[ $fail -eq 0 ]] || exit 1
echo 'Frimps foundation validation passed.'
