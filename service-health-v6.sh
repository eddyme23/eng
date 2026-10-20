#!/usr/bin/env bash
# Local checks only: never restart a service because an external site is down.
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
state=/var/lib/frimps-health
install -d -m 700 "$state"
exec 9>"$state/run.lock"
flock -n 9 || exit 0
now=$(date +%s)
listener() {
  local unit="$1" transport="$2" port="$3" sockets group pid
  sockets=$(ss -H -ln"$transport"p "( sport = :$port )") || return 1
  [[ -n $sockets ]] || return 1
  # WireGuard's socket belongs to the kernel rather than a userspace PID.
  [[ $unit != wg-quick@wg0.service ]] || return 0
  group=$(systemctl show "$unit" -p ControlGroup --value)
  [[ -n $group && $group != / ]] || return 1
  while read -r pid; do
    if grep -Fq -- ":$group" "/proc/$pid/cgroup" 2>/dev/null; then return 0; fi
  done < <(grep -oE 'pid=[0-9]+' <<<"$sockets" | cut -d= -f2)
  return 1
}
check() {
  local unit="$1" transport="$2" port="$3" failures=0 last=0 healthy=0
  # Deliberately disabled/absent services must remain disabled.
  systemctl is-enabled --quiet "$unit" || return 0
  if systemctl is-active --quiet "$unit"; then
    if [[ $transport == state ]] || listener "$unit" "$transport" "$port"; then healthy=1; fi
  fi
  if ((healthy)); then rm -f "$state/$unit.fail"; return 0; fi
  if [[ -f $state/$unit.fail ]]; then read -r failures <"$state/$unit.fail"; fi
  [[ $failures =~ ^[0-9]+$ ]] || failures=0
  failures=$((failures+1)); printf '%s\n' "$failures" >"$state/$unit.fail"
  ((failures >= 3)) || return 0
  if [[ -f $state/$unit.restart ]]; then read -r last <"$state/$unit.restart"; fi
  [[ $last =~ ^[0-9]+$ ]] || last=0
  ((now-last >= 1800)) || return 0
  printf '%s\n' "$now" >"$state/$unit.restart"
  echo "Unhealthy $unit after $failures checks; attempting recovery."
  if [[ $unit == frimps-bhttp.service ]]; then
    timeout 60 bash /usr/local/lib/frimps-v6/restart-bhttp.sh || { echo "Recovery failed: $unit"; return 0; }
  else
    timeout 30 systemctl restart "$unit" || { echo "Recovery failed: $unit"; return 0; }
  fi
  if systemctl is-active --quiet "$unit" && { [[ $transport == state ]] || listener "$unit" "$transport" "$port"; }; then
    rm -f "$state/$unit.fail"; echo "Recovery verified: $unit"
  else
    echo "Recovery not verified: $unit"
  fi
}
# Check the protocol's own listener; UDP services are not probed with fake logins.
while read -r unit transport port; do
  if [[ $unit == frimps-slowdns.service && -f /etc/frimps-v6/vaydns.env ]]; then port=5301; fi
  check "$unit" "$transport" "$port"
done <<'UNITS'
frimps-v6-dropbear.service t 143
frimps-v6-ssh-backend.service t 2222
frimps-v6-sshws.service t 3103
frimps-v6-payloadgate.service t 3102
frimps-v6-tlsmux.service t 9443
frimps-slowdns.service u 53
frimps-vaydns.service u 5302
frimps-dns-dispatch.service u 53
hysteria1-server.service u 36712
hysteria2-server.service u 443
zivpn.service u 5667
frimps-udp-custom.service u 36717
frimps-socksip.service state 0
frimps-badvpn.service state 0
frimps-openvpn-udp.service u 1194
frimps-openvpn-tcp.service t 1194
frimps-openvpn-gateway.service state 0
frimps-openvpn-stunnel.service state 0
frimps-openvpn-bshield.service t 10081
wg-quick@wg0.service u 4000
nginx.service state 0
haproxy.service t 443
UNITS
# These ports are configurable: read the installed production settings.
for item in 'bhttp BHTTP_PORT frimps-bhttp.service' 'hcr HCR_PORT frimps-hcr.service' 'hcr-tls HCR_TLS_PORT frimps-hcr-tls.service'; do
  read -r config variable unit <<<"$item"
  file="/etc/frimps-v6/$config.env"
  [[ -f $file ]] || continue
  source "$file"
  port="${!variable:-}"
  [[ $port =~ ^[0-9]+$ ]] && check "$unit" t "$port"
done
exit 0
