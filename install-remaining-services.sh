#!/usr/bin/env bash
# Install ordered UDP routing and the managed WireGuard foundation.
# Protocol installers provide their own complete authenticated configurations.
set -euo pipefail

state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
die() { echo "v6 remaining services: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die 'run as root'
command -v systemctl >/dev/null 2>&1 || die 'systemd is required'
install -d -m 700 "$state_dir" /etc/frimps-v6

# The routing service is intentionally installed before consumers. All direct
# ports RETURN from its chain; range services are routed only after exceptions.
install -m 700 "$script_dir/udp-routing.sh" /usr/local/libexec/frimps-v6-udp-routing
cat > /etc/systemd/system/frimps-v6-udp-routing.service <<'EOF'
[Unit]
Description=Frimps v6 ordered UDP ingress policy
After=network-online.target
Wants=network-online.target
Before=wg-quick@wg0.service frimps-openvpn-udp.service hysteria2-server.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/frimps-v6-udp-routing apply
ExecStop=/usr/local/libexec/frimps-v6-udp-routing remove
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# WireGuard is fully local-key based; do not overwrite an unmanaged wg0.
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
  command -v wg >/dev/null 2>&1 || die 'install wireguard-tools before staging WireGuard'
  umask 077
  server_key="$(wg genkey)"
  server_pub="$(printf '%s' "$server_key" | wg pubkey)"
  cat > /etc/wireguard/wg0.conf <<EOF
# frimps-v6 managed WireGuard configuration
[Interface]
Address = 10.0.0.1/24
ListenPort = 4000
PrivateKey = $server_key
SaveConfig = false
EOF
  printf '%s\n' "$server_pub" > "$state_dir/wireguard-server-public.key"
  chmod 600 /etc/wireguard/wg0.conf "$state_dir/wireguard-server-public.key"
fi
install -m 700 "$script_dir/wireguard-accounts.sh" /usr/local/libexec/frimps-v6-wireguard-accounts
[[ -f "$state_dir/wireguard-users.json" ]] || printf '[]\n' > "$state_dir/wireguard-users.json"
chmod 600 "$state_dir/wireguard-users.json"
cat > /etc/sysctl.d/99-frimps-v6-wireguard.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
cat > /etc/systemd/system/frimps-v6-wireguard-nat.service <<'EOF'
[Unit]
Description=Frimps v6 WireGuard forwarding and NAT
After=network-online.target
Wants=network-online.target
Before=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/frimps-v6-wireguard-nat apply
ExecStop=/usr/local/libexec/frimps-v6-wireguard-nat remove
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
install -m 700 "$script_dir/wireguard-nat.sh" /usr/local/libexec/frimps-v6-wireguard-nat
chmod 700 /usr/local/libexec/frimps-v6-wireguard-nat
cat > /etc/cron.d/frimps-v6-wireguard-expiry <<'EOF'
13 0 * * * root /usr/local/libexec/frimps-v6-wireguard-accounts cleanup >/dev/null 2>&1
EOF

systemctl daemon-reload
echo 'UDP routing and WireGuard foundations staged. Protocol installers enable their managed services.'
