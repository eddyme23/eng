#!/usr/bin/env bash
set -euo pipefail

ports=(143 3102 3103 3104 9443)
units=(frimps-v6-dropbear frimps-v6-gfraw frimps-v6-sshws frimps-v6-tlsmux frimps-v6-payloadgate)

[[ "${EUID}" -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
for unit in "${units[@]}"; do systemctl cat "$unit" >/dev/null 2>&1 || { echo "Missing staged unit: $unit" >&2; exit 1; }; done

for port in "${ports[@]}"; do
  if ss -ltn "( sport = :$port )" | tail -n +2 | grep -q .; then
    echo "Refusing to start: TCP $port is already in use." >&2
    exit 2
  fi
done

systemctl start frimps-v6-dropbear
systemctl start frimps-v6-gfraw
systemctl start frimps-v6-sshws
systemctl start frimps-v6-tlsmux
systemctl start frimps-v6-payloadgate

for unit in "${units[@]}"; do
  systemctl is-active --quiet "$unit" || { echo "Failed unit: $unit" >&2; exit 3; }
done
echo 'v6 loopback backends are active. No public TCP listener was started.'
