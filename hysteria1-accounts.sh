#!/usr/bin/env bash
set -euo pipefail
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ui-v6.sh"
store="$state_dir/hysteria1-users.json"
clients="${V6_HYSTERIA1_CLIENT_DIR:-/etc/hysteria1/clients}"
[[ -r "$state_dir/service-options.env" ]] && source "$state_dir/service-options.env"
die(){ echo "v6 Hysteria 1: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'run as root'; command -v jq >/dev/null || die 'install jq'
action="${1:-}"; name="${2:-}"; valid(){ [[ "$1" =~ ^[a-zA-Z0-9._-]{1,64}$ ]]; }; valid_speed(){ [[ "$1" =~ ^[1-9][0-9]{0,5}$ ]]; }; commit(){ local t; t=$(mktemp "$state_dir/.hy1.XXXXXX"); printf '%s\n' "$1" > "$t"; chmod 600 "$t"; mv "$t" "$store"; }
[[ -f "$store" ]] || die 'run hysteria1-install.sh first'; install -d -m 700 "$clients"
case "$action" in
 create) V6_DOMAIN="${V6_DOMAIN:-$(jq -r '.primaryDomain // empty' "$state_dir/routes.json")}"; [[ "$V6_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die 'primary domain is missing; run install-v6.sh first'; days="${3:-}"; pass="${4:-$(openssl rand -hex 12)}"; valid "$name" || die 'invalid username'; [[ "$days" =~ ^[1-9][0-9]{0,3}$ ]] || die 'invalid days'; [[ "$pass" =~ ^[a-zA-Z0-9._-]{1,64}$ ]] || die 'password must be 1-64 letters, digits, dot, underscore, or hyphen'; jq -e --arg n "$name" '.[]|select(.name==$n)' "$store" >/dev/null && die 'account exists'; exp=$(date -u -d "+$days days" +%F); commit "$(jq --arg n "$name" --arg p "$pass" --arg e "$exp" '.+[{name:$n,password:$p,expiresAt:$e}]' "$store")"; bash "$script_dir/hysteria1-render.sh"; systemctl reset-failed hysteria1-server.service || true; systemctl enable --now hysteria1-server.service; ui_success_title 'HYSTERIA 1 ACCOUNT CREATED'; ui_kv 'Username' "$name"; ui_kv 'Domain' "$V6_DOMAIN"; ui_kv 'Port Range' '20000-50000 UDP'; ui_kv 'Auth Password' "$pass"; ui_kv 'Obfs' "${V6_HYSTERIA1_OBFS:-frEddxx}"; ui_kv 'Expiry Date' "$exp" ;;
 renew) days="${3:-}"; [[ "$days" =~ ^[1-9][0-9]{0,3}$ ]] || die 'invalid days'; jq -e --arg n "$name" '.[]|select(.name==$n)' "$store" >/dev/null || die 'account does not exist'; today=$(date -u +%F); current=$(jq -r --arg n "$name" '.[]|select(.name==$n)|.expiresAt' "$store"); base="$today"; [[ "$current" > "$today" ]] && base="$current"; exp=$(date -u -d "$base +$days days" +%F); commit "$(jq --arg n "$name" --arg e "$exp" 'map(if .name==$n then .expiresAt=$e else . end)' "$store")"; bash "$script_dir/hysteria1-render.sh"; echo "Hysteria 1 account renewed through $exp" ;;
 delete) commit "$(jq --arg n "$name" 'map(select(.name!=$n))' "$store")"; rm -f "$clients/$name.uri"; bash "$script_dir/hysteria1-render.sh" ;;
 list) jq -r '.[]|[.name,.expiresAt]|@tsv' "$store" | column -t -N NAME,EXPIRES ;;
 speed) up="${2:-}"; down="${3:-}"; valid_speed "$up" && valid_speed "$down" || die 'speeds must be positive whole Mbps values'; printf 'V6_HYSTERIA1_UP_MBPS=%q\nV6_HYSTERIA1_DOWN_MBPS=%q\n' "$up" "$down" > "$state_dir/hysteria1-speeds.env"; chmod 600 "$state_dir/hysteria1-speeds.env"; bash "$script_dir/hysteria1-render.sh"; echo "Hysteria 1 speeds updated: upload $up Mbps, download $down Mbps" ;;
 *) die 'usage: hysteria1-accounts.sh {create NAME DAYS [PASSWORD]|renew NAME DAYS|delete NAME|list|speed UP_MBPS DOWN_MBPS}' ;;
esac
