#!/usr/bin/env bash
set -euo pipefail
restart_bhttp() {
  systemctl cat frimps-bhttp.service >/dev/null 2>&1 || { echo 'BHTTP is not installed.' >&2; return 1; }
  local has_socket=false
  if systemctl cat frimps-bhttp-alt.socket >/dev/null 2>&1; then
    has_socket=true
    # The active proxy inherits the listening socket. Stop both together before rebinding.
    systemctl stop frimps-bhttp-alt.socket frimps-bhttp-alt.service || return 1
    systemctl reset-failed frimps-bhttp-alt.socket frimps-bhttp-alt.service || true
  fi
  systemctl restart frimps-bhttp.service || return 1
  systemctl is-active --quiet frimps-bhttp.service || return 1
  if [[ $has_socket == true ]]; then
    systemctl start frimps-bhttp-alt.socket || return 1
    systemctl is-active --quiet frimps-bhttp-alt.socket || return 1
  fi
  echo 'BHTTP restarted; configured listeners are active.'
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  [[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
  if ! restart_bhttp; then
    echo 'BHTTP restart failed. Recent service/socket diagnostics:' >&2
    journalctl -u frimps-bhttp -u frimps-bhttp-alt.socket -u frimps-bhttp-alt.service -n 30 --no-pager >&2 || true
    exit 1
  fi
fi
