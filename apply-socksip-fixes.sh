#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
systemctl is-active --quiet frimps-socksip-network.service || { echo 'SocksIP network is not active; run apply-udp-updates.sh first' >&2; exit 1; }
install -m 700 "$script_dir/socksip-network.sh" /usr/local/libexec/frimps-socksip-network
ip netns exec frimps-socksip sysctl -w net.ipv4.ip_forward=1
echo 'Enabled forwarding inside the SocksIP namespace and updated the boot helper.'
bash "$script_dir/socksip-audit.sh"
