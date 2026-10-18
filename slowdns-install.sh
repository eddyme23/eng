#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
case "$(uname -m)" in x86_64|amd64) ;; *) echo 'The pinned SlowDNS binary requires Linux amd64.' >&2; exit 1;; esac
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"; opts="$state_dir/service-options.env"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }; [[ -r "$opts" ]] && source "$opts"
ns="${V6_SLOWDNS_NS:-}"; [[ "$ns" =~ ^[A-Za-z0-9.-]+$ ]] || { echo 'configure a SlowDNS nameserver first' >&2; exit 1; }
# Bind the ingress interface address, leaving systemd-resolved's loopback
# DNS stubs available for the server's own DNS lookups.
ingress_if="$(ip -4 route show default | awk 'NR == 1 {for (i=1;i<=NF;i++) if ($i == "dev") {print $(i+1); exit}}')"
[[ -n "$ingress_if" ]] || { echo 'cannot determine SlowDNS ingress interface' >&2; exit 1; }
listen_ip="$(ip -4 -o addr show dev "$ingress_if" scope global | awk 'NR == 1 {split($4,a,"/"); print a[1]}')"
[[ "$listen_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'cannot determine SlowDNS ingress IPv4 address' >&2; exit 1; }
install -d -m 700 /etc/slowdns
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
url='https://raw.githubusercontent.com/fisabiliyusri/SLDNS/b667b0d15be0589cd89cd2f997873296ceb07ce2/slowdns/sldns-server'
hash='ffb4d459fe9a028f7ff4b49c4c88f2f3c5f1f78ac964fb8ca57e2dfaeb457add'
curl -fL --retry 3 -o "$tmp" "$url"; printf '%s  %s\n' "$hash" "$tmp" | sha256sum -c -
# Generate a server-specific pair only on first installation. Reinstalls must
# preserve client identity; an incomplete pair needs recovery, not replacement.
chmod 700 "$tmp"
bash "$script_dir/slowdns-keys.sh" /etc/slowdns "$tmp"
install -m 700 "$tmp" /etc/slowdns/sldns-server
cat >/etc/systemd/system/frimps-slowdns.service <<EOF
[Unit]
Description=frimps SlowDNS to OpenSSH bridge
Wants=network-online.target
After=network-online.target ssh.service frimps-v6-udp-routing.service
Requires=ssh.service frimps-v6-udp-routing.service
[Service]
ExecStart=/etc/slowdns/sldns-server -udp $listen_ip:53 -privkey-file /etc/slowdns/server.key $ns 127.0.0.1:22
Restart=on-failure
RestartSec=2
LimitNOFILE=524288
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now frimps-slowdns.service
# --now does not reload a running service after its unit changes.
systemctl restart frimps-slowdns.service
systemctl is-active --quiet frimps-slowdns.service
for attempt in {1..20}; do
  ss -H -lunp 'sport = :53' | grep -q sldns-server && break
  sleep 0.25
done
bash "$script_dir/slowdns-audit.sh" --local
echo 'SlowDNS configured on UDP 53 to OpenSSH TCP 22.'
echo "Nameserver: $ns"
echo "Public key: $(cat /etc/slowdns/server.pub)"
echo 'DNS requirement: delegate the tunnel nameserver domain with an NS record to a DNS-only hostname whose A record is this VPS IPv4.'
echo 'Check service, backend, UDP listener and delegation with: bash ./slowdns-audit.sh'
