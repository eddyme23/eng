#!/usr/bin/env bash
# Optional BHTTP transport, isolated from eng's existing listeners.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'This pinned BHTTP release requires Linux amd64.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
unit=/etc/systemd/system/frimps-bhttp.service
[[ ! -e $unit ]] || { echo 'BHTTP is already installed. Use its menu controls for status or restart.'; exit 0; }
port="${BHTTP_PORT:-90}"
source "$script_dir/bhttp-policy.sh"
bhttp_policy "$(awk '/MemTotal:/ {print int($2/1024)}' /proc/meminfo)"
sessions="${BHTTP_MAX_SESSIONS:-$BHTTP_POLICY_SESSIONS}"
[[ $port =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || { echo 'Choose a port from 1 to 65535.' >&2; exit 1; }
port=$((10#$port))
case "$port" in 22|53|80|443|1194|8433|8080|8880|2082|2086|8881|8444) echo 'Choose a separate port from eng and HCR listeners.' >&2; exit 1;; esac
[[ $sessions =~ ^[1-9][0-9]{0,3}$ ]] && ((sessions <= 8192)) || { echo 'Maximum sessions must be from 1 to 8192.' >&2; exit 1; }
for cmd in curl sha256sum ss systemctl systemd-analyze install; do command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }; done
[[ -z $(ss -H -ltn "sport = :$port") ]] || { echo "TCP $port is occupied; no service was changed." >&2; exit 1; }
[[ -n $(ss -H -ltn 'sport = :22') ]] || { echo 'OpenSSH must be listening on TCP 22.' >&2; exit 1; }
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
source_binary="$tmp_dir/bhttp-server"
curl -fL --connect-timeout 10 --max-time 120 --retry 2 -o "$source_binary" 'https://raw.githubusercontent.com/JotchuaDevz/BHTTP-LIBS/cf2bb2890f8736dcc8d6820853091007582221dc/bhttp-server-v2.4.1-btun-compat-keepalive-linux-amd64'
actual_sha=$(sha256sum -- "$source_binary"); actual_sha=${actual_sha%% *}
[[ $actual_sha == 65c1fd59e2c5690253beb435b55b15dcccfd61423aa89207c9c82a8f7f85fd28 ]] || { echo 'BHTTP checksum mismatch; installation stopped.' >&2; exit 1; }
chmod 700 "$source_binary"
"$source_binary" --self-test
install -d -o root -g root -m 700 /opt/frimps-bhttp
install -o root -g root -m 755 "$source_binary" /opt/frimps-bhttp/bhttp-server
cat > "$unit" <<EOF
[Unit]
Description=Frimps BHTTP SSH transport
Wants=network-online.target
After=network-online.target ssh.service sshd.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=exec
User=root
WorkingDirectory=/opt/frimps-bhttp
ExecStart=/opt/frimps-bhttp/bhttp-server --listen 0.0.0.0 --port $port --backend-host 127.0.0.1 --backend-port 22 --session-ttl 180 --max-sessions $sessions --request-timeout 30 --read-wait-ms 2 --sequence-wait 6 --max-requests-per-conn 2048
Restart=always
RestartSec=1s
TimeoutStopSec=15s
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
ReadOnlyPaths=/opt/frimps-bhttp
LimitNOFILE=524288
LimitCORE=0
TasksMax=512
MemoryMax=${BHTTP_POLICY_MEMORY_MB}M
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl enable --now frimps-bhttp.service
sleep 3
systemctl is-active --quiet frimps-bhttp.service || { journalctl -u frimps-bhttp -n 30 --no-pager; exit 1; }
[[ -n $(ss -H -ltn "sport = :$port") ]] || { echo 'Service has not opened the test port.' >&2; exit 1; }
install -d -m 700 "$state_dir"
printf 'BHTTP_PORT=%s\nBHTTP_MAX_SESSIONS=%s\n' "$port" "$sessions" > "$state_dir/bhttp.env"
chmod 600 "$state_dir/bhttp.env"
if [[ $port == 90 ]]; then bash "$script_dir/apply-bhttp-port.sh"; else bash "$script_dir/refresh-menu-v6.sh"; fi
printf '%s\n' "BHTTP ready on TCP $port, forwarding to OpenSSH 22." 'Use a BHTTP-compatible client and an existing SSH account.' 'Allow this TCP port through any host or provider firewall if needed.' 'A running service does not yet establish a successful app connection.'
