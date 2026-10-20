#!/usr/bin/env bash
# Optional native VayDNS + SSH, sharing public UDP 53 with existing SlowDNS.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 && $(uname -m) == x86_64 ]] || { echo 'Requires root on Linux amd64.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
[[ ! -f $state_dir/vaydns.env ]] || { bash "$script_dir/vaydns-audit.sh"; exit; }
domain="${1:-${V6_VAYDNS_DOMAIN:-}}"
[[ -n $domain ]] || { echo 'Usage: bash ./vaydns-install.sh v-fr.example.com' >&2; exit 1; }
for cmd in python3 curl tar sha256sum systemctl systemd-analyze jq ss nft flock; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 1; }; done
install -d -m 700 "$state_dir"
exec 9>"$state_dir/.vaydns-install.lock"
flock -w 30 9 || exit 1
source "$state_dir/service-options.env"
slow_domain="${V6_SLOWDNS_NS:?Install SlowDNS first}"
command_line=$(systemctl show frimps-slowdns.service -p ExecStart --value)
[[ $command_line =~ -udp[[:space:]]+([0-9.]+):53 ]] || { echo 'Expected existing SlowDNS on public IPv4 UDP 53.' >&2; exit 1; }
public_ip="${BASH_REMATCH[1]}"
# Abort before touching a working service if its current routing is unhealthy.
bash "$script_dir/slowdns-audit.sh" --local
for port in 5301 5302; do [[ -z $(ss -H -lun "( sport = :$port )") ]] || { echo "UDP $port occupied." >&2; exit 1; }; done
for unit in frimps-vaydns.service frimps-dns-dispatch.service; do
 [[ ! -e /etc/systemd/system/$unit ]] || { echo "Existing $unit requires inspection." >&2; exit 1; }
done
[[ ! -e /etc/systemd/system/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf ]] || { echo 'Existing SlowDNS dispatcher override requires inspection.' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
python3 - "$public_ip" "$slow_domain" "$domain" "$tmp/dns-dispatch.json" <<'PYCONFIG'
import json,sys
ip,slow,vay,path=sys.argv[1:]
with open(path,'w') as f: json.dump({'listen':[ip,53],'routes':{slow.lower():['127.0.0.1',5301],vay.lower():['127.0.0.1',5302]}},f)
PYCONFIG
python3 "$script_dir/dns-dispatch.py" "$tmp/dns-dispatch.json" --check
# Match the upstream commit bundled in TG's native adapter. Never execute upstream installers.
curl -fL --connect-timeout 10 --max-time 180 --retry 2 -o "$tmp/source.tgz" https://codeload.github.com/net2share/vaydns/tar.gz/a0ff70110d5e96686ab8f4c8e1c44cd09be07a75
printf '%s  %s\n' 197f9f519940a588950d1eab714aa8cd3333d3c9518fb13105fef67cd2bdfe4b "$tmp/source.tgz" | sha256sum -c -
mkdir "$tmp/source" "$tmp/toolchain"
tar -xzf "$tmp/source.tgz" -C "$tmp/source" --strip-components=1
# A private, checksum-verified toolchain leaves the system Go installation unchanged.
curl -fL --connect-timeout 10 --max-time 300 --retry 2 -o "$tmp/go.tgz" https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
printf '%s  %s\n' 77e5da33bb72aeaef1ba4418b6fe511bc4d041873cbf82e5aa6318740df98717 "$tmp/go.tgz" | sha256sum -c -
tar -xzf "$tmp/go.tgz" -C "$tmp/toolchain"
(cd "$tmp/source"; GOTOOLCHAIN=local CGO_ENABLED=0 "$tmp/toolchain/go/bin/go" build -mod=readonly -trimpath -o "$tmp/vaydns-server" ./vaydns-server)
install -d -m 700 /etc/frimps-vaydns
bash "$script_dir/slowdns-keys.sh" /etc/frimps-vaydns "$tmp/vaydns-server"
install -d -m 755 /usr/local/lib/frimps-v6 /usr/local/libexec
install -m 755 "$tmp/vaydns-server" /usr/local/libexec/frimps-vaydns
install -m 644 "$tmp/source/COPYING" /etc/frimps-vaydns/COPYING
install -m 755 "$script_dir/dns-dispatch.py" /usr/local/lib/frimps-v6/dns-dispatch.py
install -m 600 "$tmp/dns-dispatch.json" "$state_dir/dns-dispatch.json"
# Store a reversible snapshot before the first live service change.
backup=$(mktemp -d /var/backups/frimps-v6/vaydns-XXXXXXXX 2>/dev/null) || {
 install -d -m 700 /var/backups/frimps-v6
 backup=$(mktemp -d /var/backups/frimps-v6/vaydns-XXXXXXXX)
}
cp -a /etc/systemd/system/frimps-slowdns.service "$backup/slowdns.service"
printf '%s\n' "$state_dir" > "$backup/state-dir"
cat >"$tmp/frimps-vaydns.service" <<EOF
[Unit]
Description=Frimps native VayDNS to SSH
After=network-online.target ssh.service
Requires=ssh.service
[Service]
ExecStart=/usr/local/libexec/frimps-vaydns -udp 127.0.0.1:5302 -privkey-file /etc/frimps-vaydns/server.key -domain $domain -upstream 127.0.0.1:22 -record-type txt -mtu 1232
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=524288
[Install]
WantedBy=multi-user.target
EOF
cat >"$tmp/frimps-dns-dispatch.service" <<EOF
[Unit]
Description=Frimps authoritative DNS tunnel dispatcher
PartOf=frimps-slowdns.service frimps-vaydns.service
After=network-online.target frimps-slowdns.service frimps-vaydns.service
Requires=frimps-slowdns.service frimps-vaydns.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/frimps-v6/dns-dispatch.py $state_dir/dns-dispatch.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
TasksMax=32
MemoryMax=128M
[Install]
WantedBy=multi-user.target
EOF
# Reuse the validated unit command, changing only the SlowDNS listening endpoint.
python3 - "$command_line" "$tmp/slowdns-override" <<'PYOVERRIDE'
import sys,re
command=sys.argv[1].split('argv[]=',1)[1].split(' ;',1)[0]
command=re.sub(r'-udp\s+[0-9.]+:53(?=\s)', '-udp 127.0.0.1:5301',command,count=1)
with open(sys.argv[2],'w') as f:f.write('[Service]\nExecStart=\nExecStart='+command+'\n')
PYOVERRIDE
systemd-analyze verify "$tmp/frimps-vaydns.service" "$tmp/frimps-dns-dispatch.service"
recover() {
 trap - ERR
 echo "Activation failed. Restoring SlowDNS. Backup: $backup" >&2
 bash "$script_dir/rollback-vaydns.sh" "$backup" || echo 'Rollback failed; inspect service logs.' >&2
 exit 1
}
trap recover ERR
install -m 644 "$tmp/frimps-vaydns.service" /etc/systemd/system/
install -m 644 "$tmp/frimps-dns-dispatch.service" /etc/systemd/system/
install -d -m 755 /etc/systemd/system/frimps-slowdns.service.d
install -m 644 "$tmp/slowdns-override" /etc/systemd/system/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf
printf 'V6_VAYDNS_DOMAIN=%q\nV6_VAYDNS_BACKUP=%q\n' "${domain,,}" "$backup" > "$state_dir/vaydns.env"
chmod 600 "$state_dir/vaydns.env"
systemctl daemon-reload
echo 'Switching UDP 53; current SlowDNS sessions will disconnect.'
systemctl restart frimps-slowdns.service
systemctl enable --now frimps-vaydns.service frimps-dns-dispatch.service
for attempt in {1..20}; do
  if ss -H -lun 'sport = :5302' | grep -q . && ss -H -lunp 'sport = :53' | grep -q python3; then break; fi
  sleep 0.25
done
bash "$script_dir/vaydns-audit.sh" --local
trap - ERR
bash "$script_dir/refresh-menu-v6.sh"
bash "$script_dir/vaydns-audit.sh"
echo "Rollback: bash ./rollback-vaydns.sh $backup"
