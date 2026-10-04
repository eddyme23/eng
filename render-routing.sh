#!/usr/bin/env bash
set -euo pipefail

state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
routes="$state_dir/routes.json"
runtime="$state_dir/runtime.env"
cert_file="${V6_CERT_FILE:-}"
key_file="${V6_KEY_FILE:-}"
die() { echo "v6 routing renderer: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "run as root"
command -v jq >/dev/null 2>&1 || die "jq is required"
[[ -s "$routes" && -s "$state_dir/backends.json" ]] || die "run install-v6.sh and render-backends.sh first"
if [[ -s "$runtime" ]]; then source "$runtime"; fi
domain="$(jq -r '.primaryDomain' "$routes")"
[[ "$domain" != "null" && -n "$domain" ]] || die "missing primary domain"
cert_file="${cert_file:-${V6_STORED_CERT_FILE:-/etc/certificates/main.crt}}"
key_file="${key_file:-${V6_STORED_KEY_FILE:-/etc/certificates/main.key}}"

cat > "$state_dir/haproxy-443.cfg" <<EOF
global
    daemon

defaults
    mode tcp
    timeout connect 5s
    timeout client 1h
    timeout server 1h

frontend public_tcp_443
    bind :443
    default_backend main_tls_router

frontend public_plain_tcp
    bind :80
    bind :8080
    bind :8880
    default_backend ssh_http_gateway

backend ssh_http_gateway
    server ssh_http_gateway 127.0.0.1:3102

frontend public_ssh_only_tcp
    bind :2082
    bind :2086
    mode tcp
    default_backend ssh_http_gateway

backend main_tls_router
    server main_tls_router 127.0.0.1:9443

EOF

cat > "$state_dir/nginx-main-tls.conf" <<EOF
# Generated v6 staging configuration. Include only after validation.
server {
    listen 127.0.0.1:9080 http2;
    server_name $domain;

    location = /openvpn {
        proxy_pass http://127.0.0.1:10081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }

    location = / {
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:3102;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }


}

# HTTP/1.1 listener for SSH WebSocket clients.
server {
    listen 127.0.0.1:9081;
    server_name $domain;

    location = /openvpn {
        proxy_pass http://127.0.0.1:10081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }

    location = / { proxy_read_timeout 1h; proxy_send_timeout 1h; proxy_buffering off; proxy_pass http://127.0.0.1:3102; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
}
EOF

cat > "$state_dir/nginx-plain.conf" <<'EOF'
# HAProxy routes /openvpn directly to the OpenVPN WebSocket gateway.
# Other plain payloads go to the SSH payload gateway.
EOF

cat > "$state_dir/nginx-ssh-only.conf" <<'EOF'
# HAProxy owns public 2082/2086 and forwards raw SSH payloads unchanged.
EOF

chmod 600 "$state_dir/haproxy-443.cfg" "$state_dir/nginx-main-tls.conf" "$state_dir/nginx-plain.conf" "$state_dir/nginx-ssh-only.conf"
cat > "$state_dir/tlsmux.service" <<EOF
[Unit]
Description=Frimps v6 TLS multiplexer
After=network.target

[Service]
ExecStart=/usr/local/libexec/frimps-v6-tlsmux -listen 127.0.0.1:9443 -cert $cert_file -key $key_file -ssh-target 127.0.0.1:143 -http1-target 127.0.0.1:9081 -h2-target 127.0.0.1:9080
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
cat > "$state_dir/payloadgate.service" <<EOF
[Unit]
Description=Frimps v6 SSH payload gateway
After=network.target

[Service]
ExecStart=/usr/local/libexec/frimps-v6-payloadgate -listen 127.0.0.1:3102 -ssh-target 127.0.0.1:143 -ws-target 127.0.0.1:3103 -openvpn-target 127.0.0.1:10081
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
chmod 600 "$state_dir/tlsmux.service" "$state_dir/payloadgate.service"
printf 'Rendered %s/haproxy-443.cfg and %s/nginx-main-tls.conf\n' "$state_dir" "$state_dir"
