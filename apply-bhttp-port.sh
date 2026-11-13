#!/usr/bin/env bash
# Compatibility entrypoint: current BHTTP manages its own listeners.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$script_dir/apply-bhttp-crisdev.sh" "$@"
