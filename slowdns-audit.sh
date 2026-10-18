#!/usr/bin/env bash
# Read-only checks. A valid listener does not prove a phone tunnel works.
set -uo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $# == 0 || ( $# == 1 && $1 == --local ) ]] || { echo 'Use without arguments, or --local to skip public DNS queries.' >&2; exit 1; }
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
failed=0
check() { if "$@"; then printf '[OK] %s\n' "$*"; else printf '[FAIL] %s\n' "$*" >&2; failed=1; fi; }
check systemctl is-enabled --quiet frimps-slowdns.service
check systemctl is-active --quiet frimps-slowdns.service
check test -x /etc/slowdns/sldns-server
check grep -Eq -- '-udp [0-9.]+:53 .* 127\.0\.0\.1:22$' /etc/systemd/system/frimps-slowdns.service
listeners="$(ss -H -lunp 'sport = :53')"
if [[ $listeners == *sldns-server* ]]; then echo '[OK] SlowDNS owns a UDP 53 socket'; else echo '[FAIL] No SlowDNS UDP 53 socket' >&2; failed=1; fi
check python3 - <<'PY'
import socket, subprocess
from pathlib import Path
try:
    secret = bytes.fromhex(Path('/etc/slowdns/server.key').read_text().strip())
    public = bytes.fromhex(Path('/etc/slowdns/server.pub').read_text().strip())
    if len(secret) != 32 or len(public) != 32:
        raise ValueError('DNS keys must each contain 32 bytes')
    # RFC 8410 PKCS#8 X25519 private-key wrapper. Never print the private key.
    encoded = bytes.fromhex('302e020100300506032b656e04220420') + secret
    result = subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],
                            input=encoded, capture_output=True, timeout=5, check=True)
    if result.stdout != bytes.fromhex('302a300506032b656e032100') + public:
        raise ValueError('SlowDNS private/public keys do not match')
    print('[OK] Matching SlowDNS key pair')
    with socket.create_connection(('127.0.0.1',22), timeout=5) as connection:
        connection.settimeout(5)
        if not connection.recv(256).startswith(b'SSH-'):
            raise ValueError('OpenSSH backend returned no SSH banner')
    print('[OK] SSH backend on loopback TCP 22 returns a banner')
except Exception as error:
    raise SystemExit(str(error))
PY
echo 'OpenSSH authentication/forwarding policy (local default context):'
timeout 5 /usr/sbin/sshd -T -C user=frimps-audit,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22 2>/dev/null | grep -E '^(passwordauthentication|usepam|allowtcpforwarding|disableforwarding|maxstartups|logingracetime|permitrootlogin) ' || true
if command -v nft >/dev/null; then
  policy="$(nft list table ip frimps_v6_udp 2>/dev/null)"
  if [[ $policy == *'53, 443, 1194, 4000'* ]]; then echo '[OK] Frimps NAT table reserves UDP 53 (other tables/filter chains still require inspection)'; else echo '[FAIL] UDP 53 reservation missing from managed routing policy' >&2; failed=1; fi
fi
if [[ ${1:-} != --local ]]; then
  if [[ -r "$state_dir/service-options.env" ]]; then source "$state_dir/service-options.env"; fi
  ns="${V6_SLOWDNS_NS:-}"
  if [[ $ns =~ ^[A-Za-z0-9.-]+$ ]] && command -v dig >/dev/null; then
    echo "Tunnel domain: $ns"
    # Ask the parent authority for the delegation. The tunnel server itself
    # need not answer NS queries, so a recursive +short NS query can be empty.
    parent="${ns#*.}"
    authority=''
    while [[ $parent == *.* && -z $authority ]]; do
      authority="$(dig +time=2 +tries=1 +short NS "$parent" | head -n 1)"
      [[ -n $authority ]] || parent="${parent#*.}"
    done
    records=''
    if [[ $authority =~ ^[A-Za-z0-9.-]+$ ]]; then
      records="$(dig +time=2 +tries=1 @"$authority" NS "$ns" +norecurse +noall +answer +authority | awk '$4 == "NS" {print $5}')"
    fi
    if [[ -n $records ]]; then
      printf 'Delegated NS targets:\n%s\n' "$records"
      while IFS= read -r target; do
        [[ $target =~ ^[A-Za-z0-9.-]+$ ]] || continue
        addresses="$(dig +time=2 +tries=1 +short A "$target")"
        printf 'NS target %s -> %s\n' "$target" "${addresses:-NO IPv4 ANSWER}"
        [[ -n $addresses ]] || failed=1
      done <<< "$records"
    else
      echo '[FAIL] Could not confirm an NS delegation from the parent authority' >&2; failed=1
    fi
  else
    echo '[FAIL] Configure V6_SLOWDNS_NS and install dnsutils to inspect delegation' >&2; failed=1
  fi
fi
journalctl -u frimps-slowdns.service -n 20 --no-pager || true
echo 'Use the displayed DNS public key, the delegated tunnel domain, and a valid SSH account.'
echo 'DNS NS targets must resolve to the VPS public IPv4. Provider/host firewalls must allow inbound UDP 53.'
echo 'These checks do not establish a successful DNS tunnel, SSH password login, or client browsing.'
echo 'If connected without browsing, run: bash ./slowdns-flow-audit.sh SSH_USERNAME'
exit "$failed"
