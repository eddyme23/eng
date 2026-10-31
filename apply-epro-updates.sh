#!/usr/bin/env bash
# Upgrade only the explicitly selected protocol. Existing defaults stay pinned.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/epro-upgrade.py" "$@"
