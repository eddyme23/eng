#!/usr/bin/env bash
# Optional managed HCR transport; existing SSH accounts authenticate through OpenSSH.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux amd64 is required.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
if [[ -e /etc/systemd/system/frimps-hcr-tls.service ]]; then
 echo 'HCR TLS is already installed. Use the HCR TLS service controls for status and restart.'
 exit 0
fi
tmp_dir=$(mktemp -d)
cleanup() { rm -rf -- "$tmp_dir"; }
trap cleanup EXIT
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
source_binary="$tmp_dir/hcr-server"
curl -fL --connect-timeout 10 --max-time 120 --retry 2 -o "$source_binary" 'https://raw.githubusercontent.com/eddyme23/hrc-server/884d19e224a53b6ef8828d7f1bb204d9d7092a69/hcr-server'
port="${HCR_TLS_PORT:-8444}"
frame="${HCR_MAX_DOWNLOAD_FRAME:-6144}"
poll="${HCR_DOWNLOAD_POLL_TIMEOUT:-8s}"
expected_sha='68a66ed49750965680315a60ce05260cdbb77c2b86b3a80938844cb4855fa085'
[[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1024 && 10#$port <= 65535 )) || { echo 'Choose a port from 1024 to 65535.' >&2; exit 1; }
port=$((10#$port))
case "$port" in 8080|8880|2082|2086) echo 'That port belongs to eng; choose a separate port.' >&2; exit 1;; esac
[[ $frame =~ ^[1-9][0-9]{0,6}$ ]] || { echo 'Frame size must be a positive integer.' >&2; exit 1; }
[[ $poll =~ ^[1-9][0-9]*(ms|s)$ ]] || { echo 'Poll timeout must use milliseconds or seconds, such as 8s.' >&2; exit 1; }
for cmd in ss sha256sum systemctl systemd-analyze install jq timeout; do command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }; done
[[ -f $source_binary && ! -L $source_binary ]] || { echo "HCR download did not produce a regular binary file." >&2; exit 1; }
actual_sha=$(sha256sum -- "$source_binary"); actual_sha=${actual_sha%% *}
[[ $actual_sha == "$expected_sha" ]] || { echo 'Binary checksum differs from the supplied HCR release; installation stopped.' >&2; exit 1; }
[[ -z $(ss -H -ltn "sport = :$port") ]] || { echo "TCP $port is already occupied." >&2; exit 1; }
[[ -n $(ss -H -ltn 'sport = :22') ]] || { echo 'OpenSSH must be listening on TCP 22.' >&2; exit 1; }
unit=/etc/systemd/system/frimps-hcr-tls.service
[[ ! -e $unit ]] || { echo 'HCR TLS is already installed. Use service controls to restart it; no files changed.' >&2; exit 1; }
# Use the same certificate paths as eng, so certificate renewal does not leave a copied certificate stale.
[[ -r "$state_dir/runtime.env" ]] && source "$state_dir/runtime.env"
cert_file="${V6_CERT_FILE:-${V6_STORED_CERT_FILE:-/etc/certificates/main.crt}}"
key_file="${V6_KEY_FILE:-${V6_STORED_KEY_FILE:-/etc/certificates/main.key}}"
for path in "$cert_file" "$key_file"; do
 [[ $path =~ ^/[-A-Za-z0-9._/]+$ && -s $path ]] || { echo 'A readable eng certificate and key with simple absolute paths are required.' >&2; exit 1; }
done
command -v openssl >/dev/null || { echo 'openssl is required.' >&2; exit 1; }
openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null || { echo 'Certificate is invalid or expired.' >&2; exit 1; }
domain=$(jq -r '.primaryDomain // empty' "$state_dir/routes.json")
[[ $domain =~ ^[A-Za-z0-9.-]+$ ]] || { echo 'Missing eng certificate domain.' >&2; exit 1; }
cert_pub=$(openssl x509 -in "$cert_file" -pubkey -noout)
key_pub=$(openssl pkey -in "$key_file" -passin pass: -pubout)
[[ $cert_pub == "$key_pub" ]] || { echo 'Certificate and private key do not match.' >&2; exit 1; }
install -d -o root -g root -m 700 /opt/frimps-hcr-tls
install -o root -g root -m 755 "$source_binary" /opt/frimps-hcr-tls/hcr-server
version=$(/opt/frimps-hcr-tls/hcr-server -version)
[[ $version =~ ^hcr-server\ version\ [0-9]+\.[0-9]+\.[0-9]+(\ -\ Patch\ [1-9][0-9]*)?$ ]] || { echo 'Unexpected HCR version output.' >&2; exit 1; }
cat > "$unit" <<EOF
[Unit]
Description=Frimps HCR TLS SSH transport
Wants=network-online.target
After=network-online.target ssh.service sshd.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=exec
User=root
WorkingDirectory=/opt/frimps-hcr-tls
ExecStart=/opt/frimps-hcr-tls/hcr-server --listen :$port --target 127.0.0.1:22 --transport tls --tls-cert $cert_file --tls-key $key_file --max-download-frame $frame --download-poll-timeout $poll
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
ReadOnlyPaths=/opt/frimps-hcr-tls
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
systemctl enable --now frimps-hcr-tls.service
sleep 3
systemctl is-active --quiet frimps-hcr-tls.service || { journalctl -u frimps-hcr-tls -n 30 --no-pager; exit 1; }
[[ -n $(ss -H -ltn "sport = :$port") ]] || { echo 'Service has not opened the test port.' >&2; exit 1; }
timeout 10 openssl s_client -connect "127.0.0.1:$port" -servername "$domain" -verify_hostname "$domain" -verify_return_error -CApath /etc/ssl/certs -brief </dev/null || { echo 'HCR TLS certificate/handshake verification failed.' >&2; exit 1; }
install -d -m 700 "$state_dir"
printf 'HCR_TLS_PORT=%s\nHCR_MAX_DOWNLOAD_FRAME=%s\nHCR_DOWNLOAD_POLL_TIMEOUT=%s\n' "$port" "$frame" "$poll" > "$state_dir/hcr-tls.env"
chmod 600 "$state_dir/hcr-tls.env"
bash "$script_dir/refresh-menu-v6.sh"
printf '%s\n' "$version" "HCR TLS ready on TCP $port, forwarding to OpenSSH 22." "TLS server name/SNI: $domain (enable certificate verification)." 'Use HTTP Custom HCR TLS mode and an existing SSH account.' 'Allow this TCP port through any host or provider firewall if needed.' 'A running service does not yet establish a successful app connection.'
