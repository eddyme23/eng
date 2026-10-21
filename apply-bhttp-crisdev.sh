#!/usr/bin/env bash
# Only CRISDEV BHTTP: no upstream installer, XHTTP or BTUN.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 && $(uname -s) == Linux ]] || { echo 'Run as root on Linux.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
unit=/etc/systemd/system/frimps-bhttp.service
binary=/opt/frimps-bhttp/bhttp-server
socket_unit=/etc/systemd/system/frimps-bhttp-alt.socket
proxy_unit=/etc/systemd/system/frimps-bhttp-alt.service
base=/var/backups/frimps-v6/bhttp-crisdev
for cmd in curl sha256sum python3 ss systemctl systemd-analyze install flock realpath; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 1; }; done
install -d -m 700 "$state_dir"
exec 9>"$state_dir/.bhttp-update.lock"
flock -w 30 9 || exit 1
files=("$unit" "$binary" "$state_dir/bhttp.env" "$socket_unit" "$proxy_unit")
units=(frimps-bhttp.service frimps-bhttp-alt.socket frimps-bhttp-alt.service)
restore() {
 local file item failed=0
 for item in frimps-bhttp-alt.socket frimps-bhttp-alt.service frimps-bhttp.service; do
  systemctl stop "$item" 2>/dev/null || true
  systemctl disable "$item" 2>/dev/null || true
 done
 for file in "${files[@]}"; do
  if [[ -f $backup$file ]]; then
   install -d "$(dirname "$file")" || return 1
   cp -a "$backup$file" "$file" || return 1
  else rm -f "$file" || return 1; fi
 done
 systemctl daemon-reload || return 1
 systemctl reset-failed "${units[@]}" 2>/dev/null || true
 for item in "${units[@]}"; do
  [[ ! -f $backup/$item.enabled ]] || systemctl enable "$item" || failed=1
  [[ ! -f $backup/$item.active ]] || systemctl start "$item" || failed=1
 done
 return "$failed"
}
if [[ ${1:-} == --rollback ]]; then
 backup=$(realpath -e -- "${2:?Supply the backup printed by this updater}")
 [[ $backup == "$base/"* && -f $backup/manifest ]] || { echo 'Invalid migration backup.' >&2; exit 1; }
 restore
 echo "Previous BHTTP engine and ports restored from $backup"
 exit 0
fi
[[ $# == 0 || ( $# == 1 && $1 == --install ) ]] || { echo 'Use --install or --rollback DIRECTORY.' >&2; exit 1; }
if [[ -e $unit ]]; then grep -q '^ExecStart=/opt/frimps-bhttp/bhttp-server ' "$unit" || { echo 'Unrecognized BHTTP unit.' >&2; exit 1; }; fi
for file in "$socket_unit" "$proxy_unit"; do
 if [[ -e $file ]]; then
  grep -q '^Description=Frimps BHTTP alternate port' "$file" || { echo "Unrecognized alternate-port unit: $file. No change made." >&2; exit 1; }
 fi
done
[[ -n $(ss -H -ltn 'sport = :22') ]] || { echo 'OpenSSH must listen on TCP 22.' >&2; exit 1; }
source "$script_dir/bhttp-ports.sh"
bhttp_select_ports
source "$script_dir/bhttp-policy.sh"
bhttp_policy "$(awk '/MemTotal:/ {print int($2/1024)}' /proc/meminfo)"
case "$(uname -m)" in
 x86_64|amd64) arch=amd64; hash=e7315241cca11acc2c483604f94ea80905248fc5a751954eec67497cb7f7e82b ;;
 aarch64|arm64) arch=arm64; hash=50ddb78a0c1378edb788ce91875754a3acf84d12c4dcbc7044f9d31f6488eede ;;
 *) echo 'Only amd64 and arm64 are supported.' >&2; exit 1;;
esac
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
commit=cda976b8a18a559d0941416892deceecb9a4b105
curl -fL --connect-timeout 10 --max-time 180 --retry 2 -o "$tmp/bhttp-server" "https://raw.githubusercontent.com/CristianBatero/BHTTP_CRISDEV/$commit/bin/$arch/bilola-server"
printf '%s  %s\n' "$hash" "$tmp/bhttp-server" | sha256sum -c -
chmod 700 "$tmp/bhttp-server"
python3 "$script_dir/bhttp-probe.py" --candidate "$tmp/bhttp-server"
listeners=''
for port in "${BHTTP_SELECTED_PORTS[@]}"; do listeners+="${listeners:+,}0.0.0.0:$port"; done
cat >"$tmp/frimps-bhttp.service" <<EOF
[Unit]
Description=Frimps CRISDEV BHTTP SSH transport
Wants=network-online.target
After=network-online.target ssh.service sshd.service
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
Type=exec
User=root
WorkingDirectory=/opt/frimps-bhttp
ExecStart=/opt/frimps-bhttp/bhttp-server --listen $listeners --target 127.0.0.1:22 --session-timeout 180s
Restart=always
RestartSec=1s
TimeoutStopSec=15s
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
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
install -d -m 700 /opt/frimps-bhttp
if [[ ! -e $binary ]]; then
 sed "s|/opt/frimps-bhttp/bhttp-server --listen|$tmp/bhttp-server --listen|" "$tmp/frimps-bhttp.service" > "$tmp/verify.service"
 systemd-analyze verify "$tmp/verify.service"
else systemd-analyze verify "$tmp/frimps-bhttp.service"; fi
install -d -m 700 "$base"
backup=$(mktemp -d "$base/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
for file in "${files[@]}"; do [[ ! -f $file ]] || cp --parents -a "$file" "$backup/"; done
for item in "${units[@]}"; do
 systemctl is-enabled --quiet "$item" && touch "$backup/$item.enabled" || true
 systemctl is-active --quiet "$item" && touch "$backup/$item.active" || true
done
printf 'ENG BHTTP CRISDEV migration\n' > "$backup/manifest"
recover() {
 trap - ERR
 echo "BHTTP activation failed. Restoring previous setup. Backup: $backup" >&2
 restore || echo "Recovery failed; inspect $backup and BHTTP logs." >&2
 exit 1
}
trap recover ERR
echo "Switching BHTTP; active sessions will disconnect. Backup: $backup"
for item in frimps-bhttp-alt.socket frimps-bhttp-alt.service; do
 if systemctl cat "$item" >/dev/null 2>&1; then systemctl disable --now "$item"; fi
done
install -m 755 "$tmp/bhttp-server" "$binary.new"
mv -f "$binary.new" "$binary"
install -m 644 "$tmp/frimps-bhttp.service" "$unit"
{
 printf 'BHTTP_ENGINE=crisdev\nBHTTP_COMMIT=%s\nBHTTP_PORT=%s\n' "$commit" "${BHTTP_SELECTED_PORTS[0]}"
 printf 'BHTTP_PORTS="%s"\n' "${BHTTP_SELECTED_PORTS[*]}"
} > "$state_dir/bhttp.env"
chmod 600 "$state_dir/bhttp.env"
systemctl daemon-reload
systemctl reset-failed frimps-bhttp.service || true
systemctl enable frimps-bhttp.service
systemctl restart frimps-bhttp.service
ready=false
for attempt in {1..10}; do
 if python3 "$script_dir/bhttp-probe.py" --ports "${BHTTP_SELECTED_PORTS[@]}"; then ready=true; break; fi
 sleep 0.5
done
[[ $ready == true ]]
systemctl is-active --quiet frimps-bhttp.service
rm -f "$socket_unit" "$proxy_unit"
systemctl daemon-reload
trap - ERR
bash "$script_dir/refresh-menu-v6.sh"
echo "CRISDEV BHTTP active on TCP ${BHTTP_SELECTED_PORTS[*]}, forwarding to SSH 22."
echo "Rollback: bash ./apply-bhttp-crisdev.sh --rollback $backup"
echo 'Local probes do not establish mobile-network browsing; test the affected app.'
