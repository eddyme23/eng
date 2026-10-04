#!/usr/bin/env bash
set -euo pipefail
[[ "${EUID}" -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ "${V6_CONFIRM_STOP_BACKENDS:-}" == YES ]] || {
  echo 'Refusing to stop SSH backends without V6_CONFIRM_STOP_BACKENDS=YES.' >&2
  exit 1
}
systemctl stop frimps-v6-payloadgate frimps-v6-tlsmux frimps-v6-sshws frimps-v6-gfraw frimps-v6-dropbear
echo 'v6 loopback backends stopped.'
