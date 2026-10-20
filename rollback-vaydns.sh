#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
backup=$(realpath -e -- "${1:?Supply the backup printed by vaydns-install.sh}")
[[ $backup == /var/backups/frimps-v6/vaydns-* && -f $backup/slowdns.service && -f $backup/state-dir ]] || { echo 'Invalid VayDNS backup.' >&2; exit 1; }
state_dir=$(cat "$backup/state-dir")
[[ $state_dir == /* && $state_dir != / ]] || exit 1
systemctl disable --now frimps-dns-dispatch.service frimps-vaydns.service || true
rm -f /etc/systemd/system/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf
rm -f /etc/systemd/system/frimps-dns-dispatch.service /etc/systemd/system/frimps-vaydns.service
rm -f "$state_dir/vaydns.env" "$state_dir/dns-dispatch.json"
systemctl daemon-reload
systemctl restart frimps-slowdns.service
systemctl is-active --quiet frimps-slowdns.service
# Preserve both protocols' keys, accounts and binary for recovery/reinstallation.
echo 'SlowDNS restored to its original unit endpoint; VayDNS disabled. Keys retained.'
