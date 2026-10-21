#!/usr/bin/env bash
# Expose one BHTTP server on TCP 90 and 8180, sharing session state.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
if [[ -r "$state_dir/bhttp.env" ]]; then
  source "$state_dir/bhttp.env"
  if [[ ${BHTTP_ENGINE:-} == crisdev ]]; then exec bash "$script_dir/apply-bhttp-crisdev.sh"; fi
fi
unit=/etc/systemd/system/frimps-bhttp.service
[[ -f $unit && -s "$state_dir/bhttp.env" ]] || { echo 'Install BHTTP first using bhttp-install.sh.' >&2; exit 1; }
grep -q '^ExecStart=/opt/frimps-bhttp/bhttp-server ' "$unit" || { echo 'Unrecognized BHTTP unit; no change made.' >&2; exit 1; }
source "$state_dir/bhttp.env"
if [[ $BHTTP_PORT != 90 && -n $(ss -H -ltn 'sport = :90') ]]; then echo 'TCP 90 is occupied; no change made.' >&2; exit 1; fi
proxy_bin=/lib/systemd/systemd-socket-proxyd
[[ -x $proxy_bin ]] || proxy_bin=/usr/lib/systemd/systemd-socket-proxyd
[[ -x $proxy_bin ]] || { echo 'systemd-socket-proxyd is required.' >&2; exit 1; }
if [[ $BHTTP_PORT != 8180 && -n $(ss -H -ltn 'sport = :8180') ]] && ! systemctl is-active --quiet frimps-bhttp-alt.socket; then
 echo 'TCP 8180 is occupied; no change made.' >&2; exit 1
fi
for suffix in socket service; do
 path="/etc/systemd/system/frimps-bhttp-alt.$suffix"
 if [[ -e $path ]]; then grep -q '^Description=Frimps BHTTP alternate port' "$path" || { echo 'Unmanaged alternate-port unit; no change made.' >&2; exit 1; }; fi
done
backup="/var/backups/frimps-v6/bhttp-port-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup"
cp -a "$unit" "$backup/frimps-bhttp.service"
cp -a "$state_dir/bhttp.env" "$backup/bhttp.env"
for suffix in socket service; do
 path="/etc/systemd/system/frimps-bhttp-alt.$suffix"
 [[ ! -e $path ]] || cp -a "$path" "$backup/frimps-bhttp-alt.$suffix"
done
rollback() {
 systemctl disable --now frimps-bhttp-alt.socket frimps-bhttp-alt.service 2>/dev/null || true
 for suffix in socket service; do
  path="/etc/systemd/system/frimps-bhttp-alt.$suffix"
  if [[ -e "$backup/frimps-bhttp-alt.$suffix" ]]; then cp -a "$backup/frimps-bhttp-alt.$suffix" "$path"; else rm -f "$path"; fi
 done
 cp -a "$backup/frimps-bhttp.service" "$unit"
 cp -a "$backup/bhttp.env" "$state_dir/bhttp.env"
 systemctl daemon-reload
 systemctl restart frimps-bhttp.service || true
 [[ ! -e "$backup/frimps-bhttp-alt.socket" ]] || systemctl enable --now frimps-bhttp-alt.socket || true
}
trap 'rollback' ERR
sed -i -E 's/--port [0-9]+/--port 90/; s/^CapabilityBoundingSet=.*/CapabilityBoundingSet=CAP_NET_BIND_SERVICE/; /^AmbientCapabilities=/d' "$unit"
sed -i '/^CapabilityBoundingSet=/a AmbientCapabilities=CAP_NET_BIND_SERVICE' "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl restart frimps-bhttp.service
sleep 2
systemctl is-active --quiet frimps-bhttp.service
[[ -n $(ss -H -ltn 'sport = :90') ]]
sed -i '/^BHTTP_PORTS=/d; s/^BHTTP_PORT=.*/BHTTP_PORT=90/' "$state_dir/bhttp.env"
cat > /etc/systemd/system/frimps-bhttp-alt.socket <<'EOF'
[Unit]
Description=Frimps BHTTP alternate port socket

[Socket]
ListenStream=0.0.0.0:8180
NoDelay=true

[Install]
WantedBy=sockets.target
EOF
cat > /etc/systemd/system/frimps-bhttp-alt.service <<EOF
[Unit]
Description=Frimps BHTTP alternate port proxy
Requires=frimps-bhttp.service
After=frimps-bhttp.service

[Service]
ExecStart=$proxy_bin 127.0.0.1:90
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
EOF
systemd-analyze verify /etc/systemd/system/frimps-bhttp-alt.socket /etc/systemd/system/frimps-bhttp-alt.service
systemctl daemon-reload
systemctl stop frimps-bhttp-alt.socket frimps-bhttp-alt.service || true
systemctl enable --now frimps-bhttp-alt.socket
[[ -n $(ss -H -ltn 'sport = :8180') ]]
printf 'BHTTP_PORTS="90 8180"\n' >> "$state_dir/bhttp.env"
trap - ERR
bash "$script_dir/refresh-menu-v6.sh"
echo "BHTTP is available on TCP 90 and 8180. Backup: $backup"
echo 'Use either port in your BHTTP client and allow TCP 90 and 8180 through any host/provider firewall.'
