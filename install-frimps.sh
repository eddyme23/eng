#!/usr/bin/env bash
# Fresh-server Frimps installer for Debian 12. It installs the prerequisites,
# obtains a Cloudflare DNS-01 certificate, configures every Frimps protocol,
# then enables all Frimps-managed services for boot.
set -euo pipefail

repo_url='https://github.com/eddyme23/eng.git'
repo_dir=/root/eng
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir=/etc/frimps-v6

die() { printf 'Frimps installer: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }
valid_token() { [[ "$1" =~ ^[A-Za-z0-9._-]{12,128}$ ]]; }
valid_zivpn_password() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }
random_token() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 16
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then tr -d '-\n' </proc/sys/kernel/random/uuid
  else od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
  fi
}
ask() {
  local value
  if [[ -n "$2" ]]; then read -r -e -p "$1 [$2]: " -i "$2" value
  else read -r -p "$1: " value
  fi
  printf '%s' "${value:-$2}"
}

[[ $EUID -eq 0 ]] || die 'run as root'

# The one-line raw GitHub invocation runs a copy without the companion files.
# Bootstrap the complete, reviewable repository before doing any installation.
if [[ ! -f "$script_dir/install-v6.sh" ]]; then
  command -v apt-get >/dev/null || die 'supported only on Debian 12'
  note 'Fetching the Frimps repository'
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git
  if [[ -d "$repo_dir/.git" ]]; then
    [[ "$(git -C "$repo_dir" remote get-url origin)" == "$repo_url" ]] || die "repository origin does not match $repo_url"
    git -C "$repo_dir" pull --ff-only origin main
  elif [[ -e "$repo_dir" ]]; then
    die "$repo_dir exists but is not a Frimps Git repository"
  else
    git clone --depth 1 "$repo_url" "$repo_dir"
  fi
  exec bash "$repo_dir/install-frimps.sh" --from-repository
fi

[[ -r /etc/os-release ]] || die 'cannot identify the operating system'
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" == 12 ]] || die 'this installer currently supports Debian 12 only'

note 'Frimps fresh-server setup'
printf 'Cloudflare DNS validation is used to issue a certificate for the primary domain.\n\n'
# A retry after an interrupted fresh installation must preserve generated UDP
# credentials when the corresponding prompt is left blank.
if [[ -r "$state_dir/service-options.env" ]]; then
  # shellcheck disable=SC1090
  source "$state_dir/service-options.env"
fi
previous_zivpn_password="${V6_ZIVPN_PASSWORD:-}"
previous_hy2_password="${V6_HYSTERIA2_OBFS:-}"
domain="$(ask 'Primary domain' '')"
valid_host "$domain" || die 'primary domain is invalid'
email="$(ask "Let's Encrypt email" '')"
[[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die 'email is invalid'

# Intentionally not silent: the user requested the Cloudflare token be shown
# while it is typed. It is never echoed later or written to logs.
read -r -p 'Cloudflare API token (shown while typing): ' cf_token
valid_token "$cf_token" || die 'Cloudflare API token is invalid'

slowdns_ns="$(ask 'SlowDNS nameserver' "ns-$domain")"
valid_host "$slowdns_ns" || die 'SlowDNS nameserver is invalid'
shared_obfs="$(ask 'Shared Hysteria 1 / ZiVPN obfuscation' "${V6_HYSTERIA1_OBFS:-frimps-9d4a7f21}")"
[[ "$shared_obfs" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die 'obfuscation is invalid'
read -r -p 'ZiVPN / Hysteria 1 password (shown while typing; blank = securely generate): ' zivpn_password
if [[ -z "$zivpn_password" ]]; then zivpn_password="${previous_zivpn_password:-$(random_token)}"; fi
valid_zivpn_password "$zivpn_password" || die 'ZiVPN password must be 1-64 letters, digits, dot, underscore, or hyphen'
read -r -s -p 'Hysteria 2 Salamander password (blank = securely generate): ' hy2_password; printf '\n'
if [[ -z "$hy2_password" ]]; then hy2_password="${previous_hy2_password:-$(random_token)}"; fi
valid_token "$hy2_password" || die 'Hysteria 2 password must be 12-128 letters, digits, dot, underscore, or hyphen'
enable_bbr="$(ask 'Enable native kernel BBR when available (yes/no)' 'yes')"
[[ "$enable_bbr" =~ ^(yes|no)$ ]] || die 'answer yes or no for BBR'

note 'Installing Debian dependencies'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates curl wget git jq openssl unzip tar \
  iproute2 nftables net-tools procps dnsutils cron \
  nginx haproxy dropbear-bin openvpn easy-rsa stunnel4 \
  nodejs npm golang-go wireguard-tools python3 \
  certbot python3-certbot-dns-cloudflare

download_release_asset() {
  local owner="$1" repo="$2" asset="$3" destination="$4" meta url digest actual
  meta="$(mktemp)"
  curl -fsSL --retry 3 "https://api.github.com/repos/$owner/$repo/releases/latest" -o "$meta"
  url="$(jq -r --arg asset "$asset" '.assets[] | select(.name == $asset) | .browser_download_url' "$meta")"
  digest="$(jq -r --arg asset "$asset" '.assets[] | select(.name == $asset) | .digest // empty' "$meta" | sed 's/^sha256://')"
  [[ "$url" == https://* && "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || die "verified release asset is unavailable: $owner/$repo/$asset"
  curl -fL --retry 3 -o "$destination" "$url"
  actual="$(sha256sum "$destination" | awk '{print $1}')"
  [[ "$actual" == "$digest" ]] || die "SHA-256 verification failed for $asset"
  rm -f "$meta"
}

install_hysteria2() {
  command -v hysteria >/dev/null 2>&1 && return
  note 'Installing verified Hysteria 2 release'
  local temp; temp="$(mktemp -d)"
  download_release_asset apernet hysteria hysteria-linux-amd64 "$temp/hysteria"
  install -m 755 "$temp/hysteria" /usr/local/bin/hysteria
  hysteria version >/dev/null
  rm -rf "$temp"
}

install_singbox() {
  command -v sing-box >/dev/null 2>&1 && return
  note 'Installing verified sing-box release'
  local temp version asset; temp="$(mktemp -d)"
  version="$(curl -fsSL --retry 3 https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name')"
  [[ "$version" =~ ^v[0-9] ]] || die 'could not determine sing-box release'
  asset="sing-box_${version#v}_linux_amd64.deb"
  download_release_asset SagerNet sing-box "$asset" "$temp/sing-box.deb"
  dpkg -i "$temp/sing-box.deb" || apt-get -f install -y
  sing-box version >/dev/null
  rm -rf "$temp"
}

install_hysteria2
install_singbox

if [[ "$enable_bbr" == yes ]]; then
  note 'Configuring BBR when the running kernel supports it'
  if sysctl net.ipv4.tcp_available_congestion_control | grep -qw bbr; then
    cat >/etc/sysctl.d/99-frimps-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -q -p /etc/sysctl.d/99-frimps-bbr.conf
  else
    printf 'BBR is unavailable in this kernel; continuing without it.\n' >&2
  fi
fi

note "Obtaining the primary-domain TLS certificate from Let's Encrypt"
systemctl stop nginx haproxy 2>/dev/null || true
install -d -m 700 /etc/letsencrypt
cf_credentials=/etc/letsencrypt/cloudflare.ini
umask 077
printf 'dns_cloudflare_api_token = %s\n' "$cf_token" > "$cf_credentials"
unset cf_token
certbot certonly --non-interactive --agree-tos --email "$email" \
  --dns-cloudflare --dns-cloudflare-credentials "$cf_credentials" \
  --dns-cloudflare-propagation-seconds 60 --cert-name "$domain" \
  --renew-with-new-domains -d "$domain"
cert_file="/etc/letsencrypt/live/$domain/fullchain.pem"
key_file="/etc/letsencrypt/live/$domain/privkey.pem"
[[ -s "$cert_file" && -s "$key_file" ]] || die 'certificate issuance did not produce expected files'

export V6_DOMAIN="$domain" V6_CERT_FILE="$cert_file" V6_KEY_FILE="$key_file"
export V6_HYSTERIA1_OBFS="$shared_obfs" V6_HYSTERIA2_OBFS="$hy2_password"
export V6_ZIVPN_OBFS="$shared_obfs" V6_ZIVPN_PASSWORD="$zivpn_password"

note 'Configuring Frimps core services'
bash "$script_dir/install-v6.sh"
{
  printf 'V6_SLOWDNS_NS=%q\n' "$slowdns_ns"
  printf 'V6_HYSTERIA1_OBFS=%q\n' "$shared_obfs"
  printf 'V6_HYSTERIA2_OBFS=%q\n' "$hy2_password"
  printf 'V6_ZIVPN_OBFS=%q\n' "$shared_obfs"
  printf 'V6_ZIVPN_PASSWORD=%q\n' "$zivpn_password"
} > "$state_dir/service-options.env"
chmod 600 "$state_dir/service-options.env"
bash "$script_dir/render-backends.sh"
bash "$script_dir/render-routing.sh"
bash "$script_dir/validate-v6.sh"
bash "$script_dir/stage-services.sh"
V6_CONFIRM_TEST_VPS=YES V6_ALLOW_ACTIVE_V6=YES V6_FRESH_INSTALL=YES bash "$script_dir/activate-test-vps.sh"

note 'Configuring OpenVPN, WireGuard, UDP services, and Hysteria'
bash "$script_dir/install-remaining-services.sh"
# Hysteria 1 deliberately requires the ordered UDP routing unit.  Start that
# prerequisite immediately after staging it, before creating the first H1
# account (which enables and starts the H1 service).
systemctl enable --now frimps-v6-udp-routing.service
bash "$script_dir/openvpn-install.sh"
bash "$script_dir/hysteria1-install.sh"
bash "$script_dir/hysteria1-accounts.sh" speed 1000 1000
# Match the GF installation model: Hysteria 1's initial account identifier and
# its auth string are the same shared ZiVPN password. No separate test user is
# created during fresh installation.
if ! jq -e --arg name "$zivpn_password" '.[] | select(.name == $name)' "$state_dir/hysteria1-users.json" >/dev/null; then
  bash "$script_dir/hysteria1-accounts.sh" create "$zivpn_password" 365 "$zivpn_password"
else
  echo 'Initial Hysteria 1 account already exists; preserving it.'
fi
bash "$script_dir/hysteria2-install.sh"
if ! jq -e 'length > 0' "$state_dir/hysteria2-users.json" >/dev/null; then
  bash "$script_dir/hysteria2-accounts.sh" create default 365
fi
bash "$script_dir/slowdns-install.sh"
bash "$script_dir/zivpn-install.sh"
bash "$script_dir/udp-custom-install.sh"
bash "$script_dir/socksip-install.sh"
if [[ ${V6_INSTALL_HCR:-0} == 1 ]]; then bash "$script_dir/hcr-install.sh"; fi
if [[ ${V6_INSTALL_HCR_TLS:-0} == 1 ]]; then bash "$script_dir/hcr-tls-install.sh"; fi

note 'Enabling every installed Frimps service for this boot and future boots'
bash "$script_dir/refresh-menu-v6.sh"
systemctl enable --now certbot.timer
bash "$script_dir/postflight-v6.sh"

required_units='frimps-v6-dropbear frimps-v6-sshws frimps-v6-payloadgate frimps-v6-tlsmux frimps-v6-udp-routing frimps-v6-wireguard-nat frimps-openvpn-nat frimps-openvpn-udp frimps-openvpn-tcp frimps-openvpn-gateway frimps-openvpn-stunnel frimps-openvpn-bshield hysteria1-server hysteria2-server wg-quick@wg0 frimps-slowdns zivpn frimps-badvpn frimps-udp-custom frimps-socksip-network frimps-socksip nginx haproxy'
failed_units=()
for unit in $required_units; do
  systemctl is-active --quiet "$unit" || failed_units+=("$unit")
done
[[ ${#failed_units[@]} -eq 0 ]] || die "services failed to start: ${failed_units[*]}"

printf '\nFrimps installation completed. Menu: frimps-v6-menu\n'
printf 'Primary domain: %s\nSlowDNS NS: %s\n' "$domain" "$slowdns_ns"
