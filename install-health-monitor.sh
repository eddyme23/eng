#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install -d -m 755 /usr/local/lib/frimps-v6
install -m 755 "$script_dir/service-health-v6.sh" /usr/local/lib/frimps-v6/service-health-v6.sh
cat >/etc/systemd/system/frimps-health.service <<'UNIT'
[Unit]
Description=Frimps guarded local service health checks
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/frimps-v6/service-health-v6.sh
TimeoutStartSec=15min
UMask=0077
UNIT
cat >/etc/systemd/system/frimps-health.timer <<'UNIT'
[Unit]
Description=Periodic Frimps service health checks
[Timer]
OnBootSec=5min
OnUnitInactiveSec=3min
Unit=frimps-health.service
[Install]
WantedBy=timers.target
UNIT
# Per-service journal rate limits retain diagnostics without changing global logs.
for unit in frimps-v6-tlsmux frimps-v6-payloadgate frimps-v6-sshws frimps-slowdns hysteria1-server hysteria2-server zivpn frimps-udp-custom frimps-socksip frimps-hcr frimps-hcr-tls frimps-bhttp; do
  systemctl cat "$unit" >/dev/null 2>&1 || continue
  install -d -m 755 "/etc/systemd/system/$unit.service.d"
  printf '[Service]\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=1000\n' >"/etc/systemd/system/$unit.service.d/70-frimps-log-limits.conf"
done
# Only rotate Frimps-owned file logs; never replace system log policies.
install -d -m 755 /etc/logrotate.d
cat >/etc/logrotate.d/frimps <<'LOGS'
/var/log/frimps/*.log {
    daily
    maxsize 20M
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root root
}
LOGS
systemctl daemon-reload
systemctl enable --now frimps-health.timer
echo 'Frimps health timer and scoped log limits installed.'
