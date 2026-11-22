#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
account="${1:-}"
identity="${2:-}"
shared=false
bundle="/etc/frimps-app-auth/bundle-$account.json"
if [[ -n $identity ]] || ! bash "$script_dir/app-ssh-auth.sh" bundle-check "$account" 2>/dev/null; then
  bundle="$(mktemp)"
  trap 'rm -f -- "$bundle"' EXIT
  if [[ -n $identity ]]; then
    bash "$script_dir/app-ssh-auth.sh" certificate-info "$account" "$identity" > "$bundle"
  else
    bash "$script_dir/app-ssh-auth.sh" shared-export "$account" > "$bundle"
  fi
  shared=true
fi
valid_ipv4() {
  local value="$1" IFS=. octet
  read -r -a octets <<<"$value"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] && ((10#$octet <= 255)) || return 1
  done
}
slowdns_public_ipv4() {
  local candidate
  candidate="$(curl -4fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if valid_ipv4 "$candidate"; then printf '%s' "$candidate"; return; fi
  candidate="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i == "src") {print $(i+1); exit}}')"
  if valid_ipv4 "$candidate"; then printf '%s' "$candidate"; return; fi
  printf 'Not detected'
}

domain="$(jq -r '.primaryDomain // empty' "$state_dir/routes.json")"
ipv4="$(slowdns_public_ipv4)"
expiry="$(jq -r .validBefore "$bundle")"
printf '\nCERTIFICATE ACCOUNT DETAILS\n'
printf '  Domain/Host: %s\n  IPv4       : %s\n  Account    : %s\n  Auth       : Certificate\n  Expiry     : %s\n' "$domain" "$ipv4" "$account" "$expiry"
printf '  SSH        : 22\n  SSL Direct : 443\n  SSL/WS     : 443\n  WebSocket  : 80, 8080, 8880, 2082, 2086\n'
if jq -e '.udpCustom.password | type == "string" and length > 0' "$bundle" >/dev/null; then
  printf '  UDP Custom : 50001-65535 (UDP; generated credential included privately in Gen JSON)\n'
elif [[ $shared != true ]]; then
  printf '  UDP Custom : renew this certificate account to provision its private UDP credential\n'
fi
if [[ -s "$state_dir/bhttp.env" ]]; then
  source "$state_dir/bhttp.env"
  ports="${BHTTP_PORTS:-${BHTTP_PORT:-}}"
  [[ -z $ports ]] || printf '  BHTTP      : %s:%s\n' "$ipv4" "${ports// /, }"
fi
if [[ -s "$state_dir/hcr.env" ]]; then
  source "$state_dir/hcr.env"
  printf '  HCR NTLS   : %s:%s\n' "$ipv4" "${HCR_PORT:-8881}"
fi
if [[ -s "$state_dir/hcr-tls.env" ]]; then
  source "$state_dir/hcr-tls.env"
  printf '  HCR TLS    : %s:%s\n' "$domain" "${HCR_TLS_PORT:-8444}"
fi
slowdns_ns='Not configured'
if [[ -r "$state_dir/service-options.env" ]]; then
  source "$state_dir/service-options.env"
  slowdns_ns="${V6_SLOWDNS_NS:-$slowdns_ns}"
fi
printf '  SlowDNS/DNSTT: %s:53 (UDP)\n  Tunnel NS  : %s\n' "$ipv4" "$slowdns_ns"
if [[ -r /etc/slowdns/server.pub ]]; then printf '  DNS PUB KEY: %s\n' "$(cat /etc/slowdns/server.pub)"; fi
printf '\n  Payload HTTP:\n  GET / HTTP/1.1[crlf]Host: %s[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]\n' "$domain"
printf '\n  Payload Enhanced:\n  GET / HTTP/1.1[crlf]Host: bug.com[crlf][crlf]PATCH / HTTP/1.1[crlf]Host: %s[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]\n' "$domain"
if [[ $shared == true ]]; then
  printf '\n  Export private Gen JSON on the original issuing VPS.\n'
else
  printf '\n  Export JSON: bash %s/app-ssh-auth.sh bundle-export %s\n' "$script_dir" "$account"
fi
printf '  Listed endpoints reflect configuration; test service availability and client browsing.\n'
