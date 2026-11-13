#!/usr/bin/env bash
# Optional test/activation path. Never called by the fresh installer.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/dnstt-ssh.py" "$@"
