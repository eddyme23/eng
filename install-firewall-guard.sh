#!/usr/bin/env bash
# Install cleanup hooks without restarting VPN services or changing protocol configs.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install -d -m 755 /usr/local/libexec /etc/systemd/system
install -m 700 "$script_dir/retire-iptables-rules.sh" /usr/local/libexec/frimps-retire-iptables-rules
install -m 700 "$script_dir/legacy-udp-cleanup.py" /usr/local/libexec/legacy-udp-cleanup.py
# Upgrade installed menu companions too: an older menu updater must not rewrite
# the repaired unit with its previous duplicated migration definition.
install -d -m 755 /usr/local/lib/frimps-v6
for name in install-firewall-guard.sh apply-legacy-udp-fix.sh apply-udp-updates.sh retire-iptables-rules.sh legacy-udp-cleanup.py udp-custom-install.sh service-health-v6.sh refresh-menu-v6.sh; do
  source="$script_dir/$name"
  target="/usr/local/lib/frimps-v6/$name"
  if [[ ! "$source" -ef "$target" ]]; then install -m 755 "$source" "$target"; fi
done
cat >/etc/systemd/system/frimps-firewall-migration.service <<'EOF'
[Unit]
Description=Retire obsolete ENG UDP Custom catch-all rules
After=netfilter-persistent.service nftables.service iptables.service ip6tables.service frimps-v6-udp-routing.service frimps-udp-custom.service
Requires=frimps-v6-udp-routing.service
Before=frimps-slowdns.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/frimps-retire-iptables-rules
RemainAfterExit=yes
TimeoutStartSec=60
[Install]
WantedBy=multi-user.target
EOF
install -d -m 755 /etc/systemd/system/frimps-udp-custom.service.d
cat >/etc/systemd/system/frimps-udp-custom.service.d/60-frimps-firewall-guard.conf <<'EOF'
[Unit]
After=frimps-v6-udp-routing.service netfilter-persistent.service nftables.service
[Service]
# Upstream's root process has its own iptables startup code. Firewall policy
# belongs to native ENG routing, not the UDP transport or its child commands.
CapabilityBoundingSet=~CAP_NET_ADMIN
ExecStartPre=+/usr/local/libexec/frimps-retire-iptables-rules
ExecStartPost=+/usr/local/libexec/frimps-retire-iptables-rules --wait-udp
ExecStopPost=+/usr/local/libexec/frimps-retire-iptables-rules --if-ready
EOF
install -d -m 755 /etc/systemd/system/frimps-v6-udp-routing.service.d
cat >/etc/systemd/system/frimps-v6-udp-routing.service.d/60-frimps-firewall-guard.conf <<'EOF'
[Unit]
After=netfilter-persistent.service nftables.service iptables.service ip6tables.service
[Service]
ExecStartPost=+/usr/local/libexec/frimps-retire-iptables-rules
EOF
# Dormant for absent units; do not enable or start another firewall manager.
# '+' runs cleanup with its required root/filesystem access even if the restore
# unit applies a different sandbox. Its unrelated restore command is untouched.
for unit in netfilter-persistent nftables iptables ip6tables; do
  install -d -m 755 "/etc/systemd/system/$unit.service.d"
  cat >"/etc/systemd/system/$unit.service.d/60-frimps-firewall-guard.conf" <<'EOF'
[Service]
ExecStartPost=+/usr/local/libexec/frimps-retire-iptables-rules --if-ready
EOF
done
systemctl daemon-reload
systemctl enable frimps-firewall-migration.service
echo 'ENG exact-rule cleanup hooks installed; VPN services were not restarted.'
