#!/usr/bin/env bash
# Apply HEX session/restart policy to production BHTTP with verified replacement.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
unit=/etc/systemd/system/frimps-bhttp.service
binary=/opt/frimps-bhttp/bhttp-server
base=/var/backups/frimps-v6/bhttp-update
[[ -f $unit && -x $binary && -f $state_dir/bhttp.env ]] || { echo 'Install production BHTTP first.' >&2; exit 1; }
exec 9>"$state_dir/.bhttp-update.lock"
flock -w 30 9 || exit 1
restore() {
  install -m 755 "$backup/bhttp-server" "$binary.restore" || return 1
  mv -f "$binary.restore" "$binary" || return 1
  cp -a "$backup/frimps-bhttp.service" "$unit" || return 1
  cp -a "$backup/bhttp.env" "$state_dir/bhttp.env" || return 1
  systemctl daemon-reload || return 1
  bash "$script_dir/restart-bhttp.sh"
}
if [[ ${1:-} == --rollback ]]; then
  backup=$(realpath -e -- "${2:?Supply the backup directory printed by the updater}")
  [[ $backup == "$base/"* && -f $backup/bhttp-server && -f $backup/frimps-bhttp.service && -f $backup/bhttp.env ]] || { echo 'Invalid BHTTP backup.' >&2; exit 1; }
  restore
  echo "Restored BHTTP from $backup"
  exit 0
fi
[[ $# == 0 ]] || { echo 'Usage: apply-bhttp-updates.sh [--rollback BACKUP_DIRECTORY]' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'This verified release requires amd64.' >&2; exit 1; }
source "$script_dir/bhttp-policy.sh"
bhttp_policy "$(awk '/MemTotal:/ {print int($2/1024)}' /proc/meminfo)"
sessions="${BHTTP_MAX_SESSIONS:-$BHTTP_POLICY_SESSIONS}"
[[ $sessions =~ ^[1-9][0-9]{0,3}$ ]] && ((sessions <= 8192)) || { echo 'Choose 1-8192 sessions.' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
curl -fL --connect-timeout 10 --max-time 120 --retry 2 -o "$tmp/bhttp-server" 'https://raw.githubusercontent.com/JotchuaDevz/BHTTP-LIBS/cf2bb2890f8736dcc8d6820853091007582221dc/bhttp-server-v2.4.1-btun-compat-keepalive-linux-amd64'
printf '%s  %s\n' 65c1fd59e2c5690253beb435b55b15dcccfd61423aa89207c9c82a8f7f85fd28 "$tmp/bhttp-server" | sha256sum -c -
chmod 700 "$tmp/bhttp-server"
timeout 20 "$tmp/bhttp-server" --self-test
# Stage and validate the candidate before touching a running service.
cp -a "$unit" "$tmp/frimps-bhttp.service"
sed -i -E "s/--max-sessions [0-9]+/--max-sessions $sessions/; s/^Restart=.*/Restart=always/; s/^RestartSec=.*/RestartSec=1s/; s/^LimitNOFILE=.*/LimitNOFILE=524288/; s/^MemoryMax=.*/MemoryMax=${BHTTP_POLICY_MEMORY_MB}M/" "$tmp/frimps-bhttp.service"
systemd-analyze verify "$tmp/frimps-bhttp.service"
install -d -m 700 "$base"
backup=$(mktemp -d "$base/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
cp -a "$binary" "$backup/bhttp-server"
cp -a "$unit" "$backup/frimps-bhttp.service"
cp -a "$state_dir/bhttp.env" "$backup/bhttp.env"
echo "BHTTP sessions will disconnect. Backup: $backup"
recover() {
  trap - ERR
  echo 'BHTTP update failed; restoring the previous engine and settings.' >&2
  restore || echo "Automatic recovery failed; inspect $backup and BHTTP logs." >&2
  exit 1
}
trap recover ERR
install -m 755 "$tmp/bhttp-server" "$binary.new"
mv -f "$binary.new" "$binary"
cp -a "$tmp/frimps-bhttp.service" "$unit"
sed -i "s/^BHTTP_MAX_SESSIONS=.*/BHTTP_MAX_SESSIONS=$sessions/" "$state_dir/bhttp.env"
systemctl daemon-reload
bash "$script_dir/restart-bhttp.sh"
source "$state_dir/bhttp.env"
for port in ${BHTTP_PORTS:-$BHTTP_PORT}; do
  ss -H -ltn "( sport = :$port )" | grep -q .
done
trap - ERR
bash "$script_dir/refresh-menu-v6.sh"
printf 'BHTTP updated: %s sessions, memory ceiling %s MB. Ports preserved.\n' "$sessions" "$BHTTP_POLICY_MEMORY_MB"
echo "Rollback: bash ./apply-bhttp-updates.sh --rollback $backup"
