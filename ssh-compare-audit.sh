#!/usr/bin/env bash
# Read-only evidence for comparing a working and failing SSH gateway VPS.
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
section() { printf '\n=== %s ===\n' "$1"; }
snapshot() {
 date -u '+%Y-%m-%d %H:%M:%S UTC'
 ss -Hntp '( sport = :143 or dport = :143 )' || true
 ps -C dropbear -o pid,ppid,stat,etime,wchan:24,args || true
}
if [[ ${1:-} == --watch ]]; then
 echo 'Stop TG, reconnect once, then stop it again during these 60 seconds.'
 for attempt in {1..20}; do snapshot; sleep 3; done
 exit 0
fi
section 'Host / repository / software'
hostname
 date -u '+%Y-%m-%d %H:%M:%S UTC'
uname -srmo
. /etc/os-release
printf 'OS: %s\n' "${PRETTY_NAME:-unknown}"
git -C "$script_dir" rev-parse --short HEAD 2>/dev/null || true
dpkg-query -W -f='${Package} ${Version}\n' dropbear-bin openssh-server nginx haproxy 2>/dev/null || true
section 'Gateway units, startup limits, running binary and disk binary'
for unit in frimps-v6-dropbear frimps-v6-tlsmux frimps-v6-payloadgate frimps-v6-sshws; do
 echo "--- $unit ---"
 systemctl show "$unit" -p ActiveState -p MainPID -p ExecStart -p ActiveEnterTimestamp -p TasksCurrent -p TasksMax -p LimitNOFILE --no-pager || true
 main_pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
 if [[ $main_pid =~ ^[1-9][0-9]*$ ]]; then
  sha256sum "/proc/$main_pid/exe" 2>/dev/null || true
 fi
done
sha256sum /usr/sbin/dropbear /usr/local/libexec/frimps-v6-tlsmux /usr/local/libexec/frimps-v6-payloadgate /usr/local/libexec/frimps-v6-sshws 2>/dev/null || true
section 'TLS tuning (non-secret settings only)'
grep -E '^FRIMPS_TLS_(SILENT_TIMEOUT|LOG_TIMING)=' /etc/frimps-v6/tlsmux.env 2>/dev/null || true
section 'SSH configuration and process state'
systemctl cat frimps-v6-dropbear --no-pager || true
snapshot
section 'SSH local TCP settings'
sysctl net.ipv4.tcp_fin_timeout net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes net.ipv4.ip_local_port_range 2>/dev/null || true
section 'Load / memory'
uptime
free -h
section 'Recent Dropbear errors and authentication activity'
journalctl -u frimps-v6-dropbear --since '5 minutes ago' --no-pager -n 60 || true
section 'Recent gateway events'
journalctl -u frimps-v6-tlsmux -u frimps-v6-payloadgate -u frimps-v6-sshws --since '5 minutes ago' --no-pager -n 60 || true
section 'Interpretation'
echo 'Compare package versions, active command lines and each running binary against its on-disk hash.'
echo 'Different build hashes alone do not establish different source code.'
echo 'Port 143 listings contain both ends of local connections; rows are not user counts.'
echo 'A child process count alone does not establish how many clients remain unauthenticated.'
echo 'For disconnect cleanup evidence, run this script with --watch while doing one TG reconnect cycle.'
