#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "$(uname -m)" in x86_64|amd64) ;; *) echo 'SocksIP upstream binary requires Linux x86_64' >&2; exit 1 ;; esac
apt-get update
apt-get install -y curl iproute2 iptables ca-certificates
install -d -m 700 /etc/frimps-socksip
download="$(mktemp /etc/frimps-socksip/.udpServer.XXXXXX)"
trap 'rm -f "$download"' EXIT
curl -fL --retry 3 -o "$download" 'https://bitbucket.org/iopmx/udprequestserver/downloads/udpServer'
printf 'b5d5df81ebfcc331ac523fdaebd18d56b1bb52e40a4ff9f3dbe878cc3c451563  %s\n' "$download" | sha256sum -c -
install -m 700 "$download" /etc/frimps-socksip/udpServer
install -m 700 "$script_dir/socksip-network.sh" /usr/local/libexec/frimps-socksip-network
cat >/etc/systemd/system/frimps-socksip-network.service <<'EOF'
[Unit]
Description=Frimps isolated SocksIP UDP network
After=network-online.target
Wants=network-online.target
Before=frimps-socksip.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/frimps-socksip-network apply
ExecStop=/usr/local/libexec/frimps-socksip-network remove
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/frimps-socksip.service <<'EOF'
[Unit]
Description=Frimps SocksIP UDP server (public UDP 1195-3999)
After=network-online.target frimps-socksip-network.service frimps-v6-udp-routing.service
Requires=frimps-socksip-network.service frimps-v6-udp-routing.service
[Service]
WorkingDirectory=/etc/frimps-socksip
ExecStart=/usr/sbin/ip netns exec frimps-socksip /etc/frimps-socksip/udpServer -ip=169.254.240.2 -net=sipns0 -mode=system
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
echo 'SocksIP configured for public IPv4 UDP 1195-3999; uses existing managed SSH usernames/passwords and expiry dates.'
echo 'Enable with: systemctl enable --now frimps-socksip-network frimps-socksip'
