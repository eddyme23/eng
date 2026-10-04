#!/usr/bin/env bash
set -euo pipefail
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
[[ -s "$state_dir/routes.json" ]] || { echo 'run install-v6.sh first' >&2; exit 1; }
jq -n '{version:2,publicRoutes:[
  {transport:"tls-http",path:"/",backend:"ssh-websocket:3102"},
  {transport:"plain-http",path:"/",backend:"ssh-payload:3102"},
  {transport:"plain-http",path:"/openvpn",backend:"openvpn-websocket:10081"}
]}' > "$state_dir/backends.json"
chmod 600 "$state_dir/backends.json"
echo 'Rendered remaining protocol backend map.'
