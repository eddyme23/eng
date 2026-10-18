#!/usr/bin/env bash
# Enable every Frimps-managed unit that is installed on this VPS.  Existing
# running units are left running; inactive installed units are started.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
units='ssh cron certbot.timer frimps-health.timer frimps-v6-dropbear frimps-v6-ssh-backend frimps-v6-sshws frimps-v6-payloadgate frimps-v6-tlsmux frimps-hcr frimps-hcr-tls frimps-bhttp frimps-bhttp-alt.socket frimps-v6-udp-routing frimps-v6-wireguard-nat frimps-openvpn-nat frimps-openvpn-udp frimps-openvpn-tcp frimps-openvpn-gateway frimps-openvpn-stunnel frimps-openvpn-bshield hysteria1-server hysteria2-server wg-quick@wg0 frimps-slowdns zivpn frimps-badvpn frimps-udp-custom frimps-socksip-network frimps-socksip frimps-account-cleanup.timer frimps-firewall-migration nginx haproxy'
failed_units=()
for unit in $units; do
  if [[ $unit == frimps-v6-ssh-backend && ! -s ${V6_STATE_DIR:-/etc/frimps-v6}/ssh-capacity.env ]]; then continue; fi
  if systemctl cat "$unit" >/dev/null 2>&1; then
    if ! systemctl enable --now "$unit"; then
      failed_units+=("$unit")
    elif ! systemctl is-enabled --quiet "$unit" || ! systemctl is-active --quiet "$unit"; then
      failed_units+=("$unit")
    fi
  fi
done
if ((${#failed_units[@]})); then
  printf 'Could not enable/start: %s\n' "${failed_units[@]}" >&2
  exit 1
fi
echo 'Installed Frimps services are active and enabled for boot.'
