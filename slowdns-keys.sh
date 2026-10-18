#!/usr/bin/env bash
# Preserve existing client identity. Never rotate an installed pair implicitly.
set -euo pipefail
directory="${1:?key directory required}"
binary="${2:?verified SlowDNS binary required}"
install -d -m 700 "$directory"
if [[ ! -e "$directory/server.key" && ! -e "$directory/server.pub" ]]; then
  temporary="$(mktemp -d "$directory/.keys.XXXXXX")"
  trap 'rm -rf -- "$temporary"' EXIT
  "$binary" -gen-key -privkey-file "$temporary/server.key" -pubkey-file "$temporary/server.pub" >/dev/null
  for file in server.key server.pub; do
    [[ -s "$temporary/$file" ]] && [[ $(cat "$temporary/$file") =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'SlowDNS key generation failed.' >&2; exit 1; }
  done
  install -m 600 "$temporary/server.key" "$directory/server.key"
  install -m 644 "$temporary/server.pub" "$directory/server.pub"
fi
for file in server.key server.pub; do
  [[ -s "$directory/$file" ]] && [[ $(cat "$directory/$file") =~ ^[a-fA-F0-9]{64}$ ]] || {
    echo 'Incomplete or invalid SlowDNS key pair. Restore both matching files from backup; existing keys were not replaced.' >&2
    exit 1
  }
done
chmod 600 "$directory/server.key"
chmod 644 "$directory/server.pub"
