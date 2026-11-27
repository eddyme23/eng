#!/usr/bin/env bash
set -euo pipefail
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
systemctl is-enabled --quiet frimps-xray.service
systemctl is-active --quiet frimps-xray.service
systemctl is-enabled --quiet frimps-xray-cleanup.timer
systemctl is-active --quiet frimps-xray-cleanup.timer
/usr/local/libexec/frimps-xray run -test -config "$state_dir/xray.json"
for port in 13101 13102 13103 13104 13105 13106 13107; do
  ss -H -ltn "( sport = :$port )" | grep -q '127.0.0.1:' || { echo "Missing loopback Xray listener $port" >&2; exit 1; }
done
haproxy -c -f /etc/haproxy/haproxy.cfg
nginx -t
echo 'Xray configuration, loopback listeners and boot/expiry services passed.'
echo 'Client authentication, direct DNS, browsing and reconnects require live verification.'
