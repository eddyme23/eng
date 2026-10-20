#!/usr/bin/env bash
# Read-only SlowDNS transport/authentication diagnostics; no firewall changes.
set -uo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
account="${1:-}"
[[ $# == 1 && $account =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo 'Use: bash ./slowdns-flow-audit.sh SSH_USERNAME' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo '=== UTC time and existing local checks ==='
date -u
bash "$script_dir/slowdns-audit.sh" --local || true
echo '=== Actual unit command and IPv4 listener addresses ==='
command_line="$(systemctl show frimps-slowdns.service -p ExecStart --value)"
printf '%s\n' "$command_line"
ip -4 -o addr show scope global
ss -H -lunp 'sport = :53'
# Probe the address actually configured in the unit. This intentionally invalid
# base32 tunnel name should elicit a DNS error, without creating an SSH session.
# A DNS response is not proof of a successful encrypted tunnel.
if [[ $command_line =~ -udp[[:space:]]+([0-9.]+):([0-9]+) ]]; then
  listen_ip="${BASH_REMATCH[1]}"
  listen_port="${BASH_REMATCH[2]}"
  tunnel_domain="$(printf '%s\n' "$command_line" | awk '{for(i=1;i<=NF;i++) if($i == "-privkey-file") {print $(i+2); exit}}')"
  if [[ $tunnel_domain =~ ^[A-Za-z0-9.-]+$ ]] && command -v dig >/dev/null; then
    echo '=== Local DNS response probe (NXDOMAIN/FORMERR is expected; timeout is not) ==='
    dig +time=3 +tries=1 +noall +comments +answer -p "$listen_port" @"$listen_ip" "_eng-audit.$tunnel_domain" TXT
  fi
fi
echo "=== Account $account (no password or hash is printed) ==="
if id "$account"; then
  passwd -S "$account"
  chage -l "$account"
  echo '=== Effective OpenSSH policy for this account over loopback ==='
  timeout 5 /usr/sbin/sshd -T -C "user=$account,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22" 2>/dev/null |
    grep -E '^(passwordauthentication|authenticationmethods|usepam|allowtcpforwarding|disableforwarding|permitopen|forcecommand|allowusers|denyusers|allowgroups|denygroups|maxstartups|logingracetime) ' || true
else
  echo '[FAIL] This SSH account does not exist on this VPS.'
fi
echo '=== Recent SlowDNS logs (current boot only) ==='
journalctl -b -u frimps-slowdns.service --since '5 minutes ago' -n 40 --no-pager
echo '=== SSH authentication/forwarding events for this account and localhost ==='
journalctl -b -u ssh.service --since '5 minutes ago' --no-pager |
  grep -E "($account|127\.0\.0\.1|forward|channel|MaxStartups|throttl)" | tail -n 60 || true
echo '=== Loopback SSH connections ==='
ss -Hntp '( sport = :22 or dport = :22 )' | grep '127.0.0.1' | head -n 30 || true
echo '=== Complete native firewall policy (includes NAT and filter chains) ==='
timeout 5 nft -a list ruleset || true
echo '=== Legacy firewall rules, if present ==='
for tool in iptables-save iptables-legacy-save; do
  if command -v "$tool" >/dev/null; then timeout 5 "$tool" || true; fi
done
echo '=== Host internet access (HTTP status only; no tunnel credentials) ==='
curl -4 -sS --connect-timeout 3 --max-time 8 -o /dev/null -w 'HTTPS status: %{http_code}\n' https://example.com/ || true
echo 'A local response does not establish external reply delivery or successful client browsing.'
echo 'Run during one app reconnect/browsing attempt and compare its timestamps with the app log.'
