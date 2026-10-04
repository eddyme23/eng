#!/usr/bin/env bash
set -euo pipefail

state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_dir="/etc/frimps-v6"
runtime_dir="/usr/local/lib/frimps-v6"

die() { echo "v6 staging: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "run as root"
for file in haproxy-443.cfg nginx-main-tls.conf nginx-plain.conf nginx-ssh-only.conf tlsmux.service payloadgate.service; do
  [[ -s "$state_dir/$file" ]] || die "missing $file; run the render scripts first"
done
for bin in haproxy nginx go dropbear dropbearkey; do command -v "$bin" >/dev/null 2>&1 || die "install $bin on the test VPS first"; done

"$script_dir/build-tlsmux.sh"
"$script_dir/build-payloadgate.sh"
"$script_dir/build-sshws.sh"
haproxy -c -f "$state_dir/haproxy-443.cfg"
bash "$script_dir/validate-v6.sh"

install -d -m 700 "$install_dir"
install -d -m 755 "$runtime_dir" "$runtime_dir/tlsmux" "$runtime_dir/payloadgate" "$runtime_dir/sshws"
install -m 755 "$script_dir"/*.sh "$runtime_dir/"
install -m 644 "$script_dir/tlsmux/main.go" "$runtime_dir/tlsmux/main.go"
install -m 644 "$script_dir/payloadgate/main.go" "$runtime_dir/payloadgate/main.go"
install -m 644 "$script_dir/sshws/main.go" "$runtime_dir/sshws/main.go"
ln -sfn "$runtime_dir/menu-v6.sh" /usr/local/bin/frimps-v6-menu
ln -sfn "$runtime_dir/menu-v6.sh" /usr/local/bin/menu
# Fresh Debian installations can have dropbear-bin installed without an
# enabled packaged Dropbear unit, which means no host key has been generated
# yet. The loopback SSH bridge still needs a stable key after every reboot.
install -d -m 700 /etc/dropbear
if ! find /etc/dropbear -maxdepth 1 -type f -name 'dropbear_*_host_key' -size +0c | grep -q .; then
  dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key >/dev/null
  dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null
fi
chmod 600 /etc/dropbear/dropbear_*_host_key
# The rendered files already reside in install_dir when the default state
# directory is used. Copying them onto themselves makes GNU install fail.
if [[ "$state_dir" != "$install_dir" ]]; then
  install -m 600 "$state_dir/haproxy-443.cfg" "$install_dir/haproxy-443.cfg"
  install -m 600 "$state_dir/nginx-main-tls.conf" "$install_dir/nginx-main-tls.conf"
  install -m 600 "$state_dir/nginx-plain.conf" "$install_dir/nginx-plain.conf"
  install -m 600 "$state_dir/nginx-ssh-only.conf" "$install_dir/nginx-ssh-only.conf"
fi
install -m 644 "$state_dir/tlsmux.service" /etc/systemd/system/frimps-v6-tlsmux.service
install -m 644 "$state_dir/payloadgate.service" /etc/systemd/system/frimps-v6-payloadgate.service

cat > /etc/systemd/system/frimps-v6-dropbear.service <<'EOF'
[Unit]
Description=Frimps v6 loopback Dropbear SSH
After=network.target

[Service]
ExecStart=/usr/sbin/dropbear -F -E -p 127.0.0.1:143
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/frimps-v6-sshws.service <<'EOF'
[Unit]
Description=Frimps v6 loopback SSH WebSocket bridge
After=frimps-v6-dropbear.service
Requires=frimps-v6-dropbear.service

[Service]
ExecStart=/usr/local/libexec/frimps-v6-sshws -listen 127.0.0.1:3103 -ssh-target 127.0.0.1:143
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF



systemctl daemon-reload
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/frimps-v6-reload.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# These listeners load certificate files at startup. try-restart is safe for
# optional services that have not been installed on a particular server.
for unit in \
  frimps-v6-tlsmux.service \
  hysteria1-server.service hysteria2-server.service zivpn.service \
  frimps-openvpn-stunnel.service; do
  systemctl try-restart "$unit" || true
done
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/frimps-v6-reload.sh
cat > "$state_dir/STAGED.md" <<EOF
# v6 services staged

Validated and staged on $(date -u +%FT%TZ).

Menu command: /usr/local/bin/frimps-v6-menu

Nothing was enabled or restarted. Do not start HAProxy on this configuration
until an explicit migration has released public TCP 443 from the legacy stack.
EOF
chmod 600 "$state_dir/STAGED.md"
echo "v6 services staged; no listener was enabled or restarted."
