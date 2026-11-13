#!/usr/bin/env bash
# Build the production DNSTT engine without replacing the system Go compiler.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
case "$(uname -m)" in x86_64|amd64) ;; *) echo 'The default installer supports Linux amd64.' >&2; exit 1;; esac
go_root=/opt/frimps-go-1.27.4
build=/var/cache/frimps-dnstt/upstream-20260501
if [[ ! -x "$go_root/bin/go" ]]; then
  temp="$(mktemp -d /opt/frimps-go-download.XXXXXXXX)"
  trap 'rm -rf -- "$temp"' EXIT
  curl -fL --retry 3 --connect-timeout 20 -o "$temp/go.tar.gz" https://go.dev/dl/go1.27.4.linux-amd64.tar.gz
  printf '%s  %s\n' '7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840' "$temp/go.tar.gz" | sha256sum -c -
  tar -xzf "$temp/go.tar.gz" -C "$temp"
  [[ ! -e "$go_root" ]] || { echo "Incomplete compiler directory: $go_root; inspect before retrying." >&2; exit 1; }
  mv -- "$temp/go" "$go_root"
fi
python3 "$script_dir/dnstt-build.py" --implementation upstream-20260501 \
  --go "$go_root/bin/go" --target linux-amd64 --output "$build"
