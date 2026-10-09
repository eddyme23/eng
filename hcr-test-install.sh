#!/usr/bin/env bash
# Optional HCR trial; not part of the normal protocol installation.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux amd64 is required.' >&2; exit 1; }
source_binary="${1:-/root/hcr-server}"
port="${HCR_TEST_PORT:-8881}"
frame="${HCR_MAX_DOWNLOAD_FRAME:-6144}"
poll="${HCR_DOWNLOAD_POLL_TIMEOUT:-8s}"
expected_sha='68a66ed49750965680315a60ce05260cdbb77c2b86b3a80938844cb4855fa085'
[[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1024 && 10#$port <= 65535 )) || { echo 'Choose a port from 1024 to 65535.' >&2; exit 1; }
port=$((10#$port))
case "$port" in 8080|8880|2082|2086) echo 'That port belongs to eng; choose a separate port.' >&2; exit 1;; esac
[[ $frame =~ ^[1-9][0-9]{0,6}$ ]] || { echo 'Frame size must be a positive integer.' >&2; exit 1; }
[[ $poll =~ ^[1-9][0-9]*(ms|s)$ ]] || { echo 'Poll timeout must use milliseconds or seconds, such as 8s.' >&2; exit 1; }
for cmd in ss sha256sum systemctl systemd-analyze install; do command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }; done
[[ -f $source_binary && ! -L $source_binary ]] || { echo "Upload the supplied hcr-server binary to $source_binary first." >&2; exit 1; }
actual_sha=$(sha256sum -- "$source_binary"); actual_sha=${actual_sha%% *}
[[ $actual_sha == "$expected_sha" ]] || { echo 'Binary checksum differs from the supplied HCR release; installation stopped.' >&2; exit 1; }
[[ -z $(ss -H -ltn "sport = :$port") ]] || { echo "TCP $port is already occupied. Stop the existing test or choose another port." >&2; exit 1; }
[[ -n $(ss -H -ltn 'sport = :22') ]] || { echo 'OpenSSH must be listening on TCP 22.' >&2; exit 1; }
unit=/etc/systemd/system/frimps-hcr-test.service
[[ ! -e $unit ]] || { echo 'The test unit already exists. Remove it using the README instructions before reinstalling.' >&2; exit 1; }
install -d -o root -g root -m 700 /opt/frimps-hcr-test
install -o root -g root -m 755 "$source_binary" /opt/frimps-hcr-test/hcr-server
version=$(/opt/frimps-hcr-test/hcr-server -version)
[[ $version =~ ^hcr-server\ version\ [0-9]+\.[0-9]+\.[0-9]+(\ -\ Patch\ [1-9][0-9]*)?$ ]] || { echo 'Unexpected HCR version output.' >&2; exit 1; }
cat > "$unit" <<EOF
[Unit]
Description=Frimps optional HCR trial
Wants=network-online.target
After=network-online.target ssh.service sshd.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=exec
User=root
WorkingDirectory=/opt/frimps-hcr-test
ExecStart=/opt/frimps-hcr-test/hcr-server --listen :$port --target 127.0.0.1:22 --transport plain --max-download-frame $frame --download-poll-timeout $poll
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
ReadOnlyPaths=/opt/frimps-hcr-test
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
systemctl enable --now frimps-hcr-test.service
sleep 3
systemctl is-active --quiet frimps-hcr-test.service || { journalctl -u frimps-hcr-test -n 30 --no-pager; exit 1; }
[[ -n $(ss -H -ltn "sport = :$port") ]] || { echo 'Service has not opened the test port.' >&2; exit 1; }
printf '%s\n' "$version" "HCR plain trial ready on TCP $port, forwarding to OpenSSH 22." 'Use HTTP Custom HCR plain mode and an existing SSH account.' 'Allow this TCP port through any host or provider firewall if needed.' 'A running service does not yet establish a successful app connection.'
