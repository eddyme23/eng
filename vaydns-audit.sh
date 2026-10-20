#!/usr/bin/env bash
# Local service and DNS reply checks, not an authenticated browsing test.
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
[[ $# == 0 || ${1:-} == --local ]] || exit 1
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
source "$state_dir/vaydns.env"
for unit in frimps-slowdns frimps-vaydns frimps-dns-dispatch; do
 systemctl is-enabled --quiet "$unit"
 systemctl is-active --quiet "$unit"
 echo "[OK] $unit enabled and active"
done
python3 - "$state_dir/dns-dispatch.json" <<'PYPROBE'
import json,secrets,socket,struct,subprocess
from pathlib import Path
import sys
config=json.loads(Path(sys.argv[1]).read_text())
secret=bytes.fromhex(Path('/etc/frimps-vaydns/server.key').read_text().strip())
public=bytes.fromhex(Path('/etc/frimps-vaydns/server.pub').read_text().strip())
if len(secret)!=32 or len(public)!=32: raise SystemExit('Invalid VayDNS key pair')
encoded=bytes.fromhex('302e020100300506032b656e04220420')+secret
result=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=encoded,capture_output=True,check=True)
if result.stdout[-32:]!=public:raise SystemExit('VayDNS keys do not match')
print('[OK] VayDNS key pair matches')
for domain,target in config['routes'].items():
    labels=('_eng-audit.'+domain).split('.')
    query=secrets.token_bytes(2)+struct.pack('!5H',0x0100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in labels)+b'\x00\x00\x10\x00\x01'
    for endpoint in [target,config['listen']]:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(5);sock.connect(tuple(endpoint));sock.send(query);reply=sock.recv(65535)
        if len(reply)<12 or reply[:2]!=query[:2] or not reply[2]&0x80 or reply[3]&15 not in (1,3):raise SystemExit('Invalid DNS probe response')
        print('[OK] DNS reply for',domain,'via',str(endpoint),'rcode',reply[3]&15)
PYPROBE
bash "$(dirname "$0")/slowdns-audit.sh" --local
printf 'VayDNS domain: %s\nRecord type: txt\nDNSTT compatibility: OFF\nSSH backend: 127.0.0.1:22 (existing accounts)\n' "$V6_VAYDNS_DOMAIN"
printf 'VayDNS public key: %s\n' "$(cat /etc/frimps-vaydns/server.pub)"
if [[ ${1:-} != --local ]]; then
 echo 'DNS requirement: delegate this VayDNS domain with an NS record to the DNS-only VPS hostname.'
 echo 'Use the new domain/key in TG Gen; the existing SlowDNS domain/key remain unchanged.'
fi
echo 'DNS replies do not establish SSH authentication or browsing; test both app profiles.'
