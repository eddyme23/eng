#!/usr/bin/env bash
# Explicit optional networking changes; does not upgrade the server binary.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/configure-slowdns-network.py" "$@"
