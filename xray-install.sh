#!/usr/bin/env bash
# Add ENG-owned Xray without replacing administrative SSH or UDP services.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
export V6_STATE_DIR="$state_dir"
[[ $state_dir == /* ]] || { echo 'V6_STATE_DIR must be an absolute path.' >&2; exit 1; }
for command in python3 curl jq unzip sha256sum go haproxy nginx systemctl flock; do
  command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
[[ -s "$state_dir/routes.json" && -f /etc/haproxy/haproxy.cfg && -f /etc/nginx/conf.d/frimps-v6-main.conf ]] || {
  echo 'Complete the ENG base installation first.' >&2; exit 1;
}
exec 8>"$state_dir/xray-install.lock"
flock -x 8
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
version=v26.10.31
case "$(uname -m)" in x86_64) asset=Xray-linux-64.zip;; aarch64|arm64) asset=Xray-linux-arm64-v8a.zip;; *) echo 'Unsupported architecture.' >&2; exit 1;; esac
# Pin the release and verify the archive against GitHub's SHA256 asset digest.
curl -fsSL --retry 3 "https://api.github.com/repos/XTLS/Xray-core/releases/tags/$version" -o "$tmp/release.json"
digest=$(jq -r --arg name "$asset" '.assets[] | select(.name==$name) | .digest // empty' "$tmp/release.json")
[[ $digest =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Verified Xray digest unavailable.' >&2; exit 1; }
curl -fLsS --retry 3 "https://github.com/XTLS/Xray-core/releases/download/$version/$asset" -o "$tmp/xray.zip"
actual=$(sha256sum "$tmp/xray.zip"); actual=${actual%% *}
[[ $actual == "${digest#sha256:}" ]] || { echo 'Xray digest mismatch.' >&2; exit 1; }
unzip -q "$tmp/xray.zip" xray -d "$tmp"
chmod 755 "$tmp/xray"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$tmp/payloadgate" "$script_dir/payloadgate/main.go"
# Snapshot every deployed file touched, including absent files, for rollback.
backup="/var/backups/frimps-v6/xray-$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 700 "$backup"
files=("$state_dir/xray-settings.json" "$state_dir/xray-users.json" "$state_dir/xray.json" "$state_dir/xray-routes.json" "$state_dir/backends.json" "$state_dir/haproxy-443.cfg" "$state_dir/nginx-main-tls.conf" /etc/haproxy/haproxy.cfg /etc/nginx/conf.d/frimps-v6-main.conf /usr/local/libexec/frimps-xray /usr/local/libexec/frimps-v6-payloadgate /etc/systemd/system/frimps-xray.service /etc/systemd/system/frimps-xray-cleanup.service /etc/systemd/system/frimps-xray-cleanup.timer /usr/local/lib/frimps-v6/xray-manager.py /usr/local/lib/frimps-v6/xray-accounts.sh /usr/local/lib/frimps-v6/xray-menu.sh)
touch "$backup/active" "$backup/enabled"
for unit in frimps-xray.service frimps-xray-cleanup.timer; do
  systemctl cat "$unit" >/dev/null 2>&1 || continue
  if systemctl is-active --quiet "$unit"; then echo "$unit" >> "$backup/active"; fi
  if systemctl is-enabled --quiet "$unit"; then echo "$unit" >> "$backup/enabled"; fi
done
for file in "${files[@]}"; do
  if [[ -e $file || -L $file ]]; then
    # Create snapshot parents explicitly. GNU cp --parents also copies parent
    # directory attributes and can fail when the source hierarchy uses aliases.
    # Backup layout remains absolute-path based, as required by rollback below.
    install -d -m 700 -- "$(dirname -- "$backup$file")"
    cp -a -- "$file" "$backup$file"
  else printf '%s\n' "$file" >> "$backup/absent"; fi
done
rollback() {
  trap - ERR INT TERM
  echo "Xray installation failed; restoring touched files from $backup" >&2
  systemctl stop frimps-xray-cleanup.timer frimps-xray.service 2>/dev/null || true
  for unit in frimps-xray.service frimps-xray-cleanup.timer; do
    if ! grep -qxF "$unit" "$backup/enabled"; then systemctl disable "$unit" 2>/dev/null || true; fi
  done
  for file in "${files[@]}"; do
    if [[ -e "$backup$file" || -L "$backup$file" ]]; then
      cp -a -- "$backup$file" "$file.eng-xray-restore-$$"
      mv -f -- "$file.eng-xray-restore-$$" "$file"
    else rm -f -- "$file"; fi
  done
  systemctl daemon-reload
  systemctl restart frimps-v6-payloadgate || true
  systemctl reload nginx haproxy || true
  while read -r unit; do systemctl start "$unit" || true; done < "$backup/active"
  exit 1
}
trap rollback ERR INT TERM
python3 "$script_dir/xray-manager.py" init --binary "$tmp/xray" "$@"
# Overlay the live configuration, preserving the selected SSH backend and all
# existing listeners. Never regenerate SSH units on an existing installation.
cp -a /etc/haproxy/haproxy.cfg "$state_dir/haproxy-443.cfg"
cp -a /etc/nginx/conf.d/frimps-v6-main.conf "$state_dir/nginx-main-tls.conf"
python3 "$script_dir/xray-manager.py" decorate
haproxy -c -f "$state_dir/haproxy-443.cfg"
install -m 755 "$tmp/xray" /usr/local/libexec/frimps-xray.new-$$
mv -f /usr/local/libexec/frimps-xray.new-$$ /usr/local/libexec/frimps-xray
install -m 755 "$tmp/payloadgate" /usr/local/libexec/frimps-v6-payloadgate.new-$$
mv -f /usr/local/libexec/frimps-v6-payloadgate.new-$$ /usr/local/libexec/frimps-v6-payloadgate
install -m 600 "$state_dir/haproxy-443.cfg" /etc/haproxy/haproxy.cfg
install -m 600 "$state_dir/nginx-main-tls.conf" /etc/nginx/conf.d/frimps-v6-main.conf
nginx -t
install -d -m 755 /usr/local/lib/frimps-v6
for file in xray-manager.py xray-accounts.sh xray-menu.sh; do
  if [[ ! "$script_dir/$file" -ef "/usr/local/lib/frimps-v6/$file" ]]; then install -m 755 "$script_dir/$file" "/usr/local/lib/frimps-v6/$file"; fi
done
cat > /etc/systemd/system/frimps-xray.service <<EOF
[Unit]
Description=ENG Xray VLESS VMess Trojan
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/libexec/frimps-xray run -config $state_dir/xray.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/frimps-xray-cleanup.service <<EOF
[Unit]
Description=Remove expired ENG Xray accounts
[Service]
Type=oneshot
Environment=V6_STATE_DIR=$state_dir
ExecStart=/usr/bin/python3 /usr/local/lib/frimps-v6/xray-manager.py cleanup
EOF
cat > /etc/systemd/system/frimps-xray-cleanup.timer <<'EOF'
[Unit]
Description=ENG Xray account expiry timer
[Timer]
OnCalendar=*-*-* 00:01:00 UTC
Persistent=true
Unit=frimps-xray-cleanup.service
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable frimps-xray.service frimps-xray-cleanup.timer
systemctl restart frimps-xray.service
systemctl start frimps-xray-cleanup.timer
systemctl is-active --quiet frimps-xray.service
systemctl restart frimps-v6-payloadgate.service
systemctl reload nginx haproxy
trap - ERR INT TERM
echo "Xray installed. Configuration backup: $backup"
echo 'Use DNS-only A/AAAA records for direct access. REALITY and TLS names must resolve to this VPS.'
echo 'Create accounts in menu > Xray Account Management. Live app browsing/reconnect tests remain required.'
