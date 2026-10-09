#!/usr/bin/env bash
# Optional managed HCR transport; existing SSH accounts authenticate through OpenSSH.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux amd64 is required.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
if [[ -e /etc/systemd/system/frimps-hcr.service ]]; then
 echo 'HCR is already installed. Use the HCR service controls for status and restart.'
 exit 0
fi
tmp_dir=$(mktemp -d)
migrating=false
migrate_trial=false
cleanup() { code=$?; rm -rf -- "$tmp_dir"; if ((code != 0)) && [[ $migrating == true ]]; then systemctl disable --now frimps-hcr.service || true; systemctl enable --now frimps-hcr-test.service || true; fi; }
trap cleanup EXIT
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
source_binary="$tmp_dir/hcr-server"
curl -fL --connect-timeout 10 --max-time 120 --retry 2 -o "$source_binary" 'https://raw.githubusercontent.com/eddyme23/hrc-server/884d19e224a53b6ef8828d7f1bb204d9d7092a69/hcr-server'
port="${HCR_PORT:-8881}"
frame="${HCR_MAX_DOWNLOAD_FRAME:-6144}"
poll="${HCR_DOWNLOAD_POLL_TIMEOUT:-8s}"
expected_sha='68a66ed49750965680315a60ce05260cdbb77c2b86b3a80938844cb4855fa085'
[[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1024 && 10#$port <= 65535 )) || { echo 'Choose a port from 1024 to 65535.' >&2; exit 1; }
port=$((10#$port))
case "$port" in 8080|8880|2082|2086) echo 'That port belongs to eng; choose a separate port.' >&2; exit 1;; esac
[[ $frame =~ ^[1-9][0-9]{0,6}$ ]] || { echo 'Frame size must be a positive integer.' >&2; exit 1; }
[[ $poll =~ ^[1-9][0-9]*(ms|s)$ ]] || { echo 'Poll timeout must use milliseconds or seconds, such as 8s.' >&2; exit 1; }
for cmd in ss sha256sum systemctl systemd-analyze install; do command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }; done
[[ -f $source_binary && ! -L $source_binary ]] || { echo "HCR download did not produce a regular binary file." >&2; exit 1; }
actual_sha=$(sha256sum -- "$source_binary"); actual_sha=${actual_sha%% *}
[[ $actual_sha == "$expected_sha" ]] || { echo 'Binary checksum differs from the supplied HCR release; installation stopped.' >&2; exit 1; }
listener=$(ss -H -ltnp "sport = :$port")
if [[ -n $listener ]]; then
 test_pid=$(systemctl show -p MainPID --value frimps-hcr-test.service 2>/dev/null || true)
 [[ $test_pid =~ ^[1-9][0-9]*$ && $listener == *"pid=$test_pid,"* ]] || { echo "TCP $port is occupied by another service." >&2; exit 1; }
 migrate_trial=true
fi
[[ -n $(ss -H -ltn 'sport = :22') ]] || { echo 'OpenSSH must be listening on TCP 22.' >&2; exit 1; }
unit=/etc/systemd/system/frimps-hcr.service
[[ ! -e $unit ]] || { echo 'HCR is already installed. Use service controls to restart it; no files changed.' >&2; exit 1; }
if [[ $migrate_trial == true ]]; then migrating=true; systemctl disable --now frimps-hcr-test.service; fi
install -d -o root -g root -m 700 /opt/frimps-hcr
install -o root -g root -m 755 "$source_binary" /opt/frimps-hcr/hcr-server
version=$(/opt/frimps-hcr/hcr-server -version)
[[ $version =~ ^hcr-server\ version\ [0-9]+\.[0-9]+\.[0-9]+(\ -\ Patch\ [1-9][0-9]*)?$ ]] || { echo 'Unexpected HCR version output.' >&2; exit 1; }
cat > "$unit" <<EOF
[Unit]
Description=Frimps HCR plain SSH transport
Wants=network-online.target
After=network-online.target ssh.service sshd.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=exec
User=root
WorkingDirectory=/opt/frimps-hcr
ExecStart=/opt/frimps-hcr/hcr-server --listen :$port --target 127.0.0.1:22 --transport plain --max-download-frame $frame --download-poll-timeout $poll
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
ReadOnlyPaths=/opt/frimps-hcr
LimitNOFILE=4096
LimitCORE=0
TasksMax=512
MemoryMax=384M
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl enable --now frimps-hcr.service
sleep 3
systemctl is-active --quiet frimps-hcr.service || { journalctl -u frimps-hcr -n 30 --no-pager; exit 1; }
[[ -n $(ss -H -ltn "sport = :$port") ]] || { echo 'Service has not opened the test port.' >&2; exit 1; }
install -d -m 700 "$state_dir"
printf 'HCR_PORT=%s\nHCR_MAX_DOWNLOAD_FRAME=%s\nHCR_DOWNLOAD_POLL_TIMEOUT=%s\n' "$port" "$frame" "$poll" > "$state_dir/hcr.env"
chmod 600 "$state_dir/hcr.env"
migrating=false
bash "$script_dir/refresh-menu-v6.sh"
printf '%s\n' "$version" "HCR plain ready on TCP $port, forwarding to OpenSSH 22." 'Use HTTP Custom HCR plain mode and an existing SSH account.' 'Allow this TCP port through any host or provider firewall if needed.' 'A running service does not yet establish a successful app connection.'
