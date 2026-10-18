#!/usr/bin/env bash
# Optional reversible backend setup. Administrative SSH configuration is untouched.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
units='frimps-v6-tlsmux frimps-v6-payloadgate frimps-v6-sshws'
rollback_overrides() {
 for unit in $units; do
  path="/etc/systemd/system/$unit.service.d/80-frimps-ssh-backend.conf"
  if [[ -f $path ]]; then
   grep -q '^# Frimps managed SSH capacity backend$' "$path" || { echo "Unrecognized override $path" >&2; return 1; }
   rm -f -- "$path"
  fi
 done
 rm -f -- "$state_dir/ssh-capacity.env"
 systemctl daemon-reload
 systemctl restart $units
}
if [[ ${1:-} == --rollback ]]; then
 rollback_overrides
 systemctl disable --now frimps-v6-ssh-backend.service || true
 echo 'Gateways restored to the configured original backend.'
 exit 0
fi
[[ $# == 0 ]] || { echo 'Use without arguments, or --rollback.' >&2; exit 1; }
command -v python3 >/dev/null
[[ -x /usr/sbin/sshd ]] || { echo 'OpenSSH server is required.' >&2; exit 1; }
for unit in $units; do
 file="/etc/systemd/system/$unit.service"
 grep -q '^ExecStart=/usr/local/libexec/frimps-v6-' "$file" || { echo "Unrecognized unit: $unit" >&2; exit 1; }
 path="/etc/systemd/system/$unit.service.d/80-frimps-ssh-backend.conf"
 [[ ! -e $path ]] || { echo 'Capacity overrides already exist; use --rollback before reapplying.' >&2; exit 1; }
done
backend_unit=/etc/systemd/system/frimps-v6-ssh-backend.service
if [[ -e $backend_unit ]]; then grep -q '^Description=Frimps dedicated loopback OpenSSH backend$' "$backend_unit" || exit 1; fi
[[ -z $(ss -H -ltn 'sport = :2222') ]] || { echo 'TCP 2222 is occupied; no change applied.' >&2; exit 1; }
install -d -m 700 "$state_dir"
install -d -m 755 /run/sshd
config="$state_dir/sshd-backend.conf"
cat > "$config" <<'EOF'
# Frimps dedicated backend; never included by the administrative SSH daemon.
Port 2222
ListenAddress 127.0.0.1
AddressFamily inet
PidFile /run/frimps-sshd-backend.pid
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
AllowTcpForwarding yes
GatewayPorts no
PermitTunnel no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
UseDNS no
LoginGraceTime 30
MaxStartups 100:30:300
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 60
ClientAliveCountMax 3
LogLevel INFO
EOF
keys=0
for key in /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key; do
 if [[ -s $key ]]; then printf 'HostKey %s\n' "$key" >> "$config"; keys=$((keys+1)); fi
done
((keys > 0)) || { echo 'No existing OpenSSH host keys; no gateway change made.' >&2; exit 1; }
chmod 600 "$config"
/usr/sbin/sshd -t -f "$config"
cat > "$backend_unit" <<EOF
[Unit]
Description=Frimps dedicated loopback OpenSSH backend
After=network.target

[Service]
ExecStartPre=/usr/bin/install -d -m 0755 /run/sshd
ExecStartPre=/usr/sbin/sshd -t -f $config
ExecStart=/usr/sbin/sshd -D -e -f $config
Restart=on-failure
RestartSec=2
LimitNOFILE=524288

[Install]
WantedBy=multi-user.target
EOF
systemd-analyze verify "$backend_unit"
systemctl daemon-reload
systemctl enable --now frimps-v6-ssh-backend.service
python3 - <<'PY_CHECK'
import socket
with socket.create_connection(('127.0.0.1',2222),timeout=5) as s:
 s.settimeout(5)
 if not s.recv(256).startswith(b'SSH-'): raise SystemExit('New SSH backend did not return a banner; gateway settings were not changed.')
PY_CHECK
# Install tested TLS HTTP/1 routing and relay updates before switching backend.
bash "$script_dir/apply-connection-fixes.sh"
backup="/var/backups/frimps-v6/ssh-capacity-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup"
for unit in $units; do
 cp -a "/etc/systemd/system/$unit.service" "$backup/$unit.service"
done
trap 'rollback_overrides' ERR
for unit in $units; do
 file="/etc/systemd/system/$unit.service"
 exec_line="$(grep '^ExecStart=' "$file")"
 [[ $exec_line == *'-ssh-target 127.0.0.1:143'* ]] || { echo "Unexpected backend in $unit" >&2; false; }
 exec_line="${exec_line/-ssh-target 127.0.0.1:143/-ssh-target 127.0.0.1:2222}"
 install -d -m 755 "/etc/systemd/system/$unit.service.d"
 printf '# Frimps managed SSH capacity backend\n[Unit]\nAfter=frimps-v6-ssh-backend.service\nRequires=frimps-v6-ssh-backend.service\n[Service]\nExecStart=\n%s\n' "$exec_line" > "/etc/systemd/system/$unit.service.d/80-frimps-ssh-backend.conf"
done
printf 'SSH_BACKEND_TARGET=127.0.0.1:2222\n' > "$state_dir/ssh-capacity.env"
chmod 600 "$state_dir/ssh-capacity.env"
systemctl daemon-reload
systemctl restart $units
systemctl is-active --quiet frimps-v6-ssh-backend $units
V6_STATE_DIR="$state_dir" python3 - <<'PY_TUNNEL'
import json,os,socket,ssl
from pathlib import Path
state=Path(os.environ['V6_STATE_DIR'])
domain=json.loads((state/'routes.json').read_text())['primaryDomain']
context=ssl.create_default_context()
context.set_alpn_protocols(['http/1.1'])
with socket.create_connection(('127.0.0.1',443),timeout=5) as raw:
 with context.wrap_socket(raw,server_hostname=domain) as s:
  s.settimeout(5)
  s.sendall(('GET / HTTP/1.1\r\nHost: '+domain+'\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n').encode())
  header=b''
  while not header.endswith(b'\r\n\r\n'):
   part=s.recv(1)
   if not part: raise SystemExit('TLS payload closed before upgrade')
   header+=part
   if len(header)>16384: raise SystemExit('Oversized response header')
  if not header.startswith(b'HTTP/1.1 101'): raise SystemExit('TLS payload upgrade failed')
  s.sendall(b'SSH-2.0-eng-capacity-check\r\n')
  banner=b''
  while b'\n' not in banner and len(banner)<512:
   part=s.recv(512)
   if not part: break
   banner+=part
  if not banner.startswith(b'SSH-2.0-OpenSSH'): raise SystemExit('TLS payload did not reach the dedicated OpenSSH backend')
  print('Verified local TLS payload upgrade and OpenSSH banner.')
PY_TUNNEL
trap - ERR
echo "Dedicated OpenSSH backend selected. Unit backups: $backup"
echo 'Administrative SSH on 22 and HCR/BHTTP targets were not changed.'
echo 'Existing gateway sessions disconnected. The SSH server host key differs from Dropbear; verify any client host-key prompt.'
echo 'Test repeated TG reconnects and browsing. Roll back with: bash ./apply-ssh-capacity-fix.sh --rollback'
